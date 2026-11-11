// The database coverage check. It reads Postgres's own catalog, so it judges the database as it really is, not
// as the migration files describe it. Every build runs it against a fresh database built from the migrations
// (test/db.test.js), and the migration workflow runs it against production afterwards (scripts/db-check.js).
//   S1  every table has row-level security on and forced, with at most one permissive policy per action; nothing
//       in "public"; no view, function or right that lets a request around the policies; no temporary tables
//   S7  the site's role owns nothing, belongs to no other role, and holds exactly the audit-log rights it needs;
//       the audit log's policies and triggers are exactly the reviewed ones and fire always
//   S8  every variable-length column (numbers aside) has an upper size limit (or a fixed list of values) in the database
//   S12 no column for ID documents, ID numbers, face images or passwords
//   G3  no counters: primary keys are UUIDv7 from app.uuid_v7(), and keys that point at them are uuid
// Returns a list of problems in plain words; an empty list means it passes. Queries are tagged templates like
// every other query (S8), so the "our schemas" condition is written out in each one.
'use strict';

const FORBIDDEN_COLUMN = /(passport|ssn|social_security|national_id|id_number|id_document|drivers?_licen[cs]e|licen[cs]e_number|tax_id|face|selfie|biometric|password|passwd)/;
const MAX_LIMIT = 100000; // a "limit" above this many characters or bytes isn't a limit
// The roles that requests act as. dog_signin acts only inside the reviewed sign-in functions below.
const ACTING = ['dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs', 'dog_timers', 'dog_log', 'dog_work', 'dog_ghsync',
  'dog_witness'];
// 027: the timers' role. It belongs to dog_app only (so the timers run under the site's own policies), can't sign in,
// no role can act as it (027 lets dog_owner do so only while it hands the role its function), and it owns exactly one
// function, app.timers_run, the slot-gated wrapper.
const TIMERS = 'dog_timers';
// Narrow roles that only act inside their own reviewed functions (below). dog_limits (PR 6) only counts, inside the
// two emergency-brake checks; dog_erase (PR 8) only deletes, inside the one account-deletion function.
// dog_delegate (PR 7) only turns an approved draft into a post, inside app.approve_draft. dog_jevs (PR 12) only gathers
// JEVs's signals and records and carries out its decisions, inside the JEVs functions.
// dog_log (038) only adds to the public log and signs its checkpoints, inside the log functions; it alone reads the
// log's signing key.
// dog_work (042) only reads and writes the work module's tables (rooms, projects, tasks, claims, submissions, points),
// inside the work functions; it reads members' names and levels and agents' trees and rules, and nothing else. Since
// 056 it also keeps the trust Engine's tables (licenses, forecasts, precedents, findings, work orders), which are built
// on the work module's records, inside the Engine's functions.
// dog_ghsync (055, RK140) only records GitHub's facts, inside app.work_github_sync and app.work_github_wanted, for the
// dog-github function; it holds no table rights, and the site's role can't act as it. Since 057 it also records the
// changed files Third Look reads (app.tl_files_wanted, app.tl_files_record) and Aaron's proposal decisions
// (app.log_proposals_record), from the same GitHub facts.
// dog_witness (057, RK144) only reports the witness, inside app.log_witness_report, for dog-github when the log-witness
// workflow calls. It holds no table rights, and the site's role can't act as it.
const NARROW = ['dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs', 'dog_log', 'dog_work', 'dog_ghsync',
  'dog_witness'];
// The only functions allowed to run with their owner's rights (security definer). Each must be owned by the narrow
// role named for it, fix its search path, and be callable only by dog_app. Adding one is a reviewed change to this list.
// Matched by name and argument types, so an extra version of one of them with other arguments isn't covered.
// Each is pinned to the one narrow role it must run as.
const DEFINERS = {
  // 053, audit logging (NIST SP 800-53 AU, the DISA application STIG): the audit log's own triggers and helpers, and
  // the four the site calls (the session sweep, the hourly upkeep, an administrator's read and a lock's release).
  'app.audit_fill()': { owner: 'dog_owner', callers: '' },
  'app.audit_net_add()': { owner: 'dog_owner', callers: '' },
  // 056: the trust Engine records its administrators' and members' writes with it too.
  'app.audit_add(text, text, uuid, jsonb, text)': { owner: 'dog_owner', callers: 'dog_signin,dog_work' },
  'app.signin_is_locked(uuid)': { owner: 'dog_owner', callers: 'dog_signin' },
  'app.signin_locks_open()': { owner: 'dog_owner', callers: 'dog_app' },
  'app.keyfile_unpause(uuid)': { owner: 'dog_signin', callers: 'dog_owner' },
  'app.signin_failed(uuid, text, text)': { owner: 'dog_owner', callers: '' },
  'app.signin_keys_audit()': { owner: 'dog_owner', callers: '' },
  'app.sessions_audit()': { owner: 'dog_owner', callers: '' },
  'app.members_rename_audit()': { owner: 'dog_owner', callers: '' },
  'app.work_audit()': { owner: 'dog_owner', callers: '' },
  'app.session_sweep()': { owner: 'dog_owner', callers: 'dog_app' },
  'app.signin_unlock(uuid, text)': { owner: 'dog_owner', callers: 'dog_app' },
  'app.audit_admin_read(text)': { owner: 'dog_owner', callers: 'dog_app' },
  'app.audit_upkeep_run()': { owner: 'dog_owner', callers: 'dog_app' },
  'app.rate_limit_hit(text, text, integer, integer)': 'dog_signin',
  'app.email_token_issue(text, text, text, smallint)': 'dog_signin',
  'app.email_token_redeem(text, text, boolean)': 'dog_signin',
  // PR 12 added the region a traveller confirmed (p_region) to sign-in, and the check for whether a sign-in method
  // already belongs to an account, asked only after the provider has confirmed who the person is.
  // 037, after its review (H1): no longer the site's to call (it made a session with no PIN and no browser key); the
  // switched-off GitHub, X and email sign-ins that use it need the browser key and PIN step before they come back.
  'app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamp with time zone, uuid, text)': { owner: 'dog_signin', callers: '' },
  'app.sign_in_known(text, text[])': 'dog_signin',
  'app.session_resolve(text, integer)': 'dog_signin',
  'app.session_end(text)': 'dog_signin',
  // PR 15: linking and unlinking a sign-in method, from the member's own fresh session, making no session.
  'app.identity_link(text, text[], smallint, smallint, timestamp with time zone, text, text)': 'dog_signin',
  'app.identity_unlink(uuid, text)': 'dog_signin',
  // PR 15's review (F6): a traveller's sealed confirmation is used once.
  'app.region_confirm_use(text)': 'dog_signin',
  // PR 15's second review (R1): the sign-in method of the request's own session, read from the sessions table (which
  // only the sign-in role reads), so what a session makes records it and unlinking that method can undo it.
  'app.current_identity()': 'dog_signin',
  // 035: and two optional filters, a member's posts and words to search for; it also says whether each author is the
  // administrator (the one column of members it reads for that).
  'app.feed(text, uuid, integer, uuid, text)': 'dog_public',
  // 035, after its security review: the trigger that keeps app.post_search (one row per live post, for search) in step
  // with app.posts. Called by nobody directly; dog_public writes only that table, and only here.
  'app.post_search_sync()': { owner: 'dog_public', callers: '' },
  // After the re-review: a member who stops or starts being active takes out or brings back their rows.
  'app.post_search_member()': { owner: 'dog_public', callers: '' },
  'app.profile(uuid)': 'dog_public',
  'app.reportable(uuid, uuid)': 'dog_public',
  // PR 5: sign-in for agents (resolve a key, self-register, claim), in the sign-in role.
  'app.agent_resolve(text)': 'dog_signin',
  'app.agent_register(text, text, text, text)': 'dog_signin',
  'app.agent_claim(text)': 'dog_signin',
  'app.agent_claim_preview(text)': 'dog_signin',
  // PR 6: the emergency brake's checks (trigger functions; they count what the acting member or agent can't see).
  'app.posts_limit()': 'dog_limits',
  'app.agents_limit()': 'dog_limits',
  // PR 6: a ban ends the member's sessions and revokes their agents' keys, in the role that manages sessions and keys.
  'app.members_ban_cleanup()': 'dog_signin',
  // PR 8: a member deletes their own account (F8).
  'app.delete_account()': 'dog_erase',
  // Fix 2 (018, Oct 25, 2026): which of the GitHub posts the site already has JEVs hid; only those IDs, nothing more.
  'app.gh_hidden(text[])': 'dog_jevs',
  // Fix 3 (019, Oct 26, 2026): the database decides who is acting. The stamp is made only by the sign-in role and the
  // owner; any role that runs checks of who is acting may test one; only the site's role may ask to act as someone.
  // 027: and dog_timers, whose one function (app.timers_run) stamps the site itself around the timers.
  'app.actor_stamp(text, text, text, text, text)': { owner: 'dog_signin', callers: 'dog_owner,dog_timers' },
  'app.stamp_ok()': { owner: 'dog_signin', callers: 'dog_app,dog_delegate,dog_erase,dog_jevs,dog_limits,dog_owner,dog_public,dog_work' },
  'app.act_as(text, uuid, uuid, boolean, text, text, text)': 'dog_signin',
  // PR 7: approving a draft, a session's start (for the fresh sign-in), and the public receipt.
  'app.approve_draft(uuid, text)': 'dog_delegate',
  'app.receipt(uuid)': 'dog_public',
  // 059: replies. The check a reply's parent is live and the agent chain isn't past the limit (a trigger function),
  // the public thread, and where each post sits with its reply count.
  'app.replies_fill()': 'dog_public',
  'app.thread(uuid, integer)': 'dog_public',
  'app.post_places(uuid[])': 'dog_public',
  // PR 12: JEVs. Its signals (counts only), its decision, the owner's answer to a challenge, sign-up marks, whether a
  // post can be appealed, the regional gate's daily count, and the record of a settings change.
  'app.jevs_signals(text, uuid, text, text[], bigint)': 'dog_jevs',
  'app.jevs_decide(text, uuid, jsonb, text, boolean, text[], bigint, text)': 'dog_jevs',
  'app.jevs_answer(uuid, text)': 'dog_jevs',
  'app.jevs_mark(text, text, text, uuid)': 'dog_jevs',
  'app.jevs_mark_claim(text)': 'dog_jevs',
  'app.jevs_appealable(uuid)': 'dog_jevs',
  // 031 (the UI/UX review, item 9): which public questions asked about the author's own held or hidden post, by ID,
  // never a score; the same decisions app.jevs_appealable already reads, for the post's own author only.
  'app.jevs_post_reasons(uuid)': 'dog_jevs',
  'app.region_decline(text)': 'dog_jevs',
  'app.jevs_settings_audit()': 'dog_jevs',
  // PR 12, after its review: the scheduled sweep that keeps marks no longer than promised, and the commit-time check
  // that in enforce mode no post goes live without a JEVs decision.
  'app.jevs_sweep()': 'dog_jevs',
  'app.posts_scored()': 'dog_jevs',
  // PR 12 (Aaron, Oct 16, 2026): a high-risk deletion is reviewed by Aaron. His decision (delete, keep disabled or
  // restore) and the 24-hour timer that disables an account he hasn't decided on, in the role that deletes.
  'app.deletion_review_decide(uuid, text)': 'dog_erase',
  'app.deletion_reviews_expire()': 'dog_erase',
  // PR 16 (Aaron, Oct 16, 2026): agents make sub-agents. Making one, stopping a tree when an agent above stops or its
  // time is up, and lowering sub-agents with their parent, in the role that registers, claims and resolves agents; and
  // a parent's daily cap counting its whole subtree, in the role that counts for the brake.
  'app.subagent_create(text, text, text, text, text, text, integer, integer, boolean, text)': 'dog_signin',
  'app.agents_cascade()': 'dog_signin',
  'app.agent_rules_cascade()': 'dog_signin',
  'app.subagents_expire()': 'dog_signin',
  'app.agent_tree_cap()': 'dog_limits',
  // 023 (Aaron, Oct 28, 2026): signing in by posting a one-time code through giscus. The site makes a code and signs in
  // with a claimed one; only the JEVs gate's role may claim a code, for the GitHub account that posted it.
  'app.code_issue(text, text, text, text)': 'dog_signin',
  'app.code_claim(text, text, text)': { owner: 'dog_signin', callers: 'dog_jevs' },
  'app.code_claim(text, text, text, boolean)': { owner: 'dog_signin', callers: 'dog_jevs' },
  'app.founder_promote(uuid)': { owner: 'dog_owner', callers: 'dog_signin' },
  // 037 (Aaron, Nov 5, 2026): no longer the site's to call; only the PIN lanes below reach them, as their owner.
  'app.code_sign_in(text, text, text, integer, text)': { owner: 'dog_signin', callers: '' },
  // The key file (Aaron, Oct 28): signing in again with the username and file, for every account.
  'app.file_sign_in(text, text, text, text, integer, text)': { owner: 'dog_signin', callers: '' },
  // 037 (Aaron, Nov 5, 2026): the browser key and the PIN. A one-time challenge; lane 1's waiting step; the three ways in,
  // each ending at the same check (the browser's signature, checked in the database, then the PIN); the account page's
  // list, removing a browser and changing the PIN. And the sign-in role's own steps, called by nobody else: the PIN's
  // keyed hash (it reads app.pin_keys), setting and testing a PIN, the proof, adding a browser key and the wrong-PIN count.
  'app.signin_challenge(text)': 'dog_signin',
  'app.code_status(text)': 'dog_signin',
  'app.code_sign_in_pin(text, text, text, integer, text, text, bytea, text, text, text, bytea, boolean)': 'dog_signin',
  'app.file_sign_in_pin(text, text, text, text, integer, text, text, bytea, text, text, text, bytea, text)': 'dog_signin',
  // The review of 037 (M2): a browser key's public half, so the site checks lane 3's signature itself too.
  'app.browser_key_public(uuid)': 'dog_signin',
  'app.browser_sign_in(uuid, text, text, integer, text, text, text, text, bytea)': 'dog_signin',
  'app.signin_methods()': 'dog_signin',
  'app.browser_key_remove(uuid)': 'dog_signin',
  'app.pin_change(text, text)': 'dog_signin',
  'app.pin_digest(uuid, bytea, text)': { owner: 'dog_signin', callers: '' },
  'app.pin_store(uuid, text)': { owner: 'dog_signin', callers: '' },
  'app.pin_matches(uuid, text)': { owner: 'dog_signin', callers: '' },
  'app.signin_proof(bytea, text, text, bytea)': { owner: 'dog_signin', callers: '' },
  'app.browser_key_add(uuid, bytea, text)': { owner: 'dog_signin', callers: '' },
  'app.pin_wrong(uuid, text, uuid, integer)': { owner: 'dog_signin', callers: '' },
  // "Sign out everywhere" cancels the member's own key file.
  'app.file_key_revoke()': 'dog_signin',
  // 025 (the CSO's review, Oct 29): sign-in's work, called only by the sign-in role's own functions; app.sign_in, for
  // the site's role, refuses an administrator.
  'app.sign_in_core(text, text[], smallint, smallint, text, text, integer, timestamp with time zone, uuid, text)': { owner: 'dog_signin', callers: '' },
  // Getting a member ready to be administrator: one GitHub method, every session ended. Only the database owner calls it.
  'app.admin_prepare(uuid)': { owner: 'dog_signin', callers: 'dog_owner' },
  // 026 (Aaron, Oct 28): the JEVs behaviour watch. Alerts only.
  'app.watch_signin(text, text)': 'dog_signin',
  'app.watch_reach(text)': 'dog_signin',
  'app.watch_first(text)': 'dog_jevs',
  // 032: the rules that must never break, checked at most once an hour from the timer route; reads only, alerts Aaron.
  'app.invariants_check()': 'dog_jevs',
  // 033: Second Look's suggestion for a post JEVs is holding, recorded only while that hold is open; it changes no post.
  'app.sl_record(uuid, text, boolean, real, text, text)': 'dog_jevs',
  // 034 (Aaron, Oct 31: Kimi's plan, on our hosting): Second Look v1. The gate; the next eligible posts and a decision
  // on one of them, for the site's role, each checking everything itself; the report; an administrator's mode switch;
  // the unlock, the weekly report and the two triggers (the stop, and a report on a post it published), called by
  // nobody directly.
  'app.sl_eligible(uuid)': { owner: 'dog_jevs', callers: '' },
  'app.sl_claim(integer)': 'dog_jevs',
  'app.sl_decide(uuid, text, text, text, jsonb, integer, text, boolean, text, integer)': 'dog_jevs',
  'app.sl_report()': 'dog_jevs',
  'app.sl_report_core()': { owner: 'dog_jevs', callers: '' },
  'app.sl_set_mode(text)': 'dog_jevs',
  'app.sl_try_unlock()': { owner: 'dog_jevs', callers: '' },
  'app.sl_weekly_report()': { owner: 'dog_jevs', callers: '' },
  'app.sl_after_post_change()': { owner: 'dog_jevs', callers: '' },
  'app.sl_after_report()': { owner: 'dog_jevs', callers: '' },
  'app.sl_after_flag_close()': { owner: 'dog_jevs', callers: '' },
  // 036 (the design handoff of Nov 5, 2026: /decisions): the public counts of JEVs's decisions, Second Look's progress
  // and the review queue. Reads only; counts and question IDs, never a member, a post, a score or a time of day.
  'app.public_decisions()': 'dog_jevs',
  // 040 (the design handoff of Nov 5, 2026: /agents and /agents/<id>): the public agent directory and profiles, as
  // dog_public; one agent's card, called only inside them; and the count of an agent's posts removed after going live,
  // as dog_jevs (which reads every post), called only by dog_public's functions.
  'app.public_agents(uuid, integer)': 'dog_public',
  'app.public_agent(uuid)': 'dog_public',
  'app.public_agent_card(uuid)': { owner: 'dog_public', callers: '' },
  'app.public_agent_reverts(uuid)': { owner: 'dog_jevs', callers: 'dog_public' },
  // 040: recovery keys, in the sign-in role: set one with a working key, and use one for a new key; the owner's own new
  // key clears it (a trigger, called by no role).
  'app.agent_recovery_issue(text, text, text)': 'dog_signin',
  'app.agent_recover(text, text, text)': 'dog_signin',
  // After the independent review of Nov 5: which agent a recovery key is for (so JEVs checks a recovery first), and for
  // an owner, which agents have one and since when, and clearing one.
  'app.agent_recovery_subject(text)': 'dog_signin',
  'app.agent_recovery_status(uuid[])': 'dog_signin',
  'app.agent_recovery_clear(uuid)': 'dog_signin',
  'app.agent_keys_recovery_clear()': { owner: 'dog_signin', callers: '' },
  // 041 (the design handoff of Nov 5, 2026, phase 4: review for a limited, fallible human): the timer that draws the
  // 5% sample for Second Look and sends the oversight alerts (once every 10 minutes at most, whoever calls it); the
  // public oversight counts (counts only, never per person); the administrator's view of the budget and the canaries'
  // reveals; and the alerts themselves, called by nobody directly.
  'app.review_tick()': 'dog_jevs',
  'app.public_oversight()': 'dog_jevs',
  'app.review_admin()': 'dog_jevs',
  'app.review_alerts_core(timestamp with time zone, boolean)': { owner: 'dog_jevs', callers: '' },
  // After 041's independent review: an Undo's flags put back and Second Look's count taken back (called by
  // app.review_record, for a reviewer only, inside an Undo); one day's public figures, counted once; a canary made
  // ahead of time from a template. The last two are called by the timer function only.
  'app.review_reopen(uuid, timestamp with time zone)': 'dog_jevs',
  'app.review_count_day(date)': { owner: 'dog_jevs', callers: '' },
  'app.review_canary_make()': { owner: 'dog_jevs', callers: '' },
  // 030 (Aaron, Oct 29): the watch's web indicators. A signed-in request, the site's place comparison, the audit log's
  // and the settings' triggers (no role calls them directly) and the hourly sweep, callable by whoever may run the timers.
  'app.watch_session(text, text, text)': 'dog_signin',
  'app.watch_travel(text, text, integer, text)': 'dog_signin',
  'app.watch_audit()': { owner: 'dog_signin', callers: '' },
  'app.watch_settings_changed()': { owner: 'dog_signin', callers: '' },
  'app.watch_sweep()': { owner: 'dog_signin', callers: 'dog_app,dog_timers' },
  // 027 (the CSO's control 6): the timers, at most once every 50 seconds, with no timer secret on the site.
  'app.timers_run(boolean)': 'dog_timers',
  // 027 (the CSO's review, B1): the 90-day clock of an agent's tree, which an agent can't read for itself.
  'app.act_clock_expired(uuid)': 'dog_signin',
  // 038 (the design handoff of Nov 5, 2026, phase 2): the public log. Adding an entry, sealing facts and logging a post
  // are called only by the log's own functions and the post trigger; the site may run the hourly JEVs batch, log a
  // proposal decision it read on GitHub, sign the next checkpoint, report the witness's copy and read a live post's
  // opening. Only these read the signing key or write the tree.
  'app.log_append(text, timestamp with time zone, text, text, text, jsonb)': { owner: 'dog_log', callers: '' },
  'app.log_seal(bytea, jsonb)': { owner: 'dog_log', callers: '' },
  'app.log_post(uuid, uuid, uuid, text, integer, text, timestamp with time zone)': { owner: 'dog_log', callers: '' },
  'app.log_post_live()': { owner: 'dog_log', callers: '' },
  'app.log_unverified(text)': { owner: 'dog_log', callers: '' },
  'app.log_jevs_hours()': 'dog_log',
  // 057 (RK112, RK144): proposal decisions only from GitHub's facts (dog_ghsync, through the one batch function), the
  // witness's report only from the witness (dog_witness), and the timer's check that the witness has stopped, which
  // takes no input.
  'app.log_proposal(integer, text)': { owner: 'dog_log', callers: '' },
  'app.log_proposals_record(jsonb)': { owner: 'dog_log', callers: 'dog_ghsync' },
  'app.log_checkpoint()': 'dog_log',
  'app.log_witness_report(bigint, bytea, timestamp with time zone, text)': { owner: 'dog_log', callers: 'dog_witness' },
  'app.log_witness_check()': 'dog_log',
  'app.log_opening(bigint)': 'dog_log',
  // The review of 038: a random name for each account in the log (M2), the queue's trigger on each new JEVs decision
  // (H4, L1), and clearing an alarm, in a reviewed migration only (M3).
  'app.log_name(text, uuid)': { owner: 'dog_log', callers: '' },
  'app.log_queue_decision()': { owner: 'dog_log', callers: '' },
  'app.log_clear_alarm(text)': { owner: 'dog_log', callers: 'dog_owner' },
  // 042 (phase 5, the work module): the public work pages' reads, people's and agents' work (claim, submit, approve),
  // the timer's GitHub reading and tick, and the administrator's decisions, all as dog_work; the internal pieces they
  // share, called by none of them directly; and the log's work entries, which only dog_work may add.
  'app.work_summary()': 'dog_work',
  'app.work_tasks(text, text, uuid, text, uuid, integer)': 'dog_work',
  'app.work_task(uuid)': 'dog_work',
  'app.work_rooms_list()': 'dog_work',
  'app.work_room(text)': 'dog_work',
  'app.work_projects_list(text, text, text, uuid, integer)': 'dog_work',
  'app.work_project(uuid)': 'dog_work',
  'app.work_project_tasks(uuid, uuid)': 'dog_work',
  'app.work_mine()': 'dog_work',
  'app.work_project_create(text, text, text)': 'dog_work',
  'app.work_task_create(uuid, text, text, text, integer)': 'dog_work',
  'app.work_claim(uuid, text)': 'dog_work',
  'app.work_release(uuid)': 'dog_work',
  'app.work_handoff(uuid, uuid, text)': 'dog_work',
  'app.work_submit(uuid, text, text, text, text, integer)': 'dog_work',
  'app.work_approve(uuid)': 'dog_work',
  'app.work_cancel(uuid)': 'dog_work',
  // 055 (RK140): GitHub's facts only from GitHub, through the dog-github function's role, never the site's.
  'app.work_github_wanted(integer)': { owner: 'dog_work', callers: 'dog_ghsync' },
  'app.work_github_sync(jsonb)': { owner: 'dog_work', callers: 'dog_ghsync' },
  'app.work_tick()': 'dog_work',
  'app.work_admin()': 'dog_work',
  'app.work_person_decide(uuid, text, integer, text)': 'dog_work',
  'app.work_remove(text, uuid)': 'dog_work',
  'app.work_poster_decide(uuid, text, text)': 'dog_work',
  'app.work_dispute(uuid, text)': 'dog_work',
  'app.work_dispute_decide(uuid, text, text)': 'dog_work',
  'app.work_check_decide(uuid, text, text)': 'dog_work',
  'app.work_task_of(uuid)': 'dog_work',
  // Third Look (044), in shadow: the timer claims and records; an administrator switches it; its figures are public.
  // 057 (RK135, in part): the timer claims, answers and gives work back; the changed files it reads only from GitHub's
  // facts (dog_ghsync); whether it still wants a pull request, and whether a number can be an issue (for the log's
  // proposals), as internal pieces.
  'app.tl_claim(integer)': 'dog_work',
  'app.tl_decide(uuid, text, text, text, jsonb, text, boolean, boolean, integer)': 'dog_work',
  'app.tl_release(uuid, text)': 'dog_work',
  'app.tl_wants(integer)': { owner: 'dog_work', callers: '' },
  'app.tl_files_wanted(integer)': { owner: 'dog_work', callers: 'dog_ghsync' },
  'app.tl_files_record(jsonb)': { owner: 'dog_work', callers: 'dog_ghsync' },
  'app.work_github_issue_ok(integer)': { owner: 'dog_work', callers: 'dog_log' },
  'app.tl_figures()': 'dog_work',
  'app.tl_set_mode(text)': 'dog_work',
  'app.work_board(text, text, text)': 'dog_work',
  'app.work_citizen(text, text)': 'dog_work',
  'app.work_network()': 'dog_work',
  'app.work_points_ledger_backfill()': { owner: 'dog_work', callers: '' },
  // Project plans (050): milestones and planned against verified work, for every project.
  'app.work_milestone_add(uuid, text, date, boolean)': 'dog_work',
  'app.work_milestone_move(uuid, date)': 'dog_work',
  'app.work_plan(uuid)': 'dog_work',
  'app.work_featured()': 'dog_work',
  'app.work_pr_changes(integer)': 'dog_work',
  'app.work_plan_check(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_milestone_card(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_roadmap_milestones()': { owner: 'dog_work', callers: '' },
  // The administrator's console (051): one tab's figures, every read logged.
  'app.work_console(text, text, text)': 'dog_work',
  'app.work_console_integrity()': { owner: 'dog_work', callers: '' },
  'app.work_risks(uuid, uuid, smallint)': { owner: 'dog_work', callers: '' },
  'app.work_pair_watch(uuid, uuid)': { owner: 'dog_work', callers: '' },
  'app.work_may_settle(uuid, uuid)': { owner: 'dog_work', callers: '' },
  'app.work_ledger_alert()': 'dog_work',
  'app.work_evidence_add(uuid, text)': 'dog_work',
  'app.work_dispute_page(uuid)': 'dog_work',
  'app.work_disputes_list(text, uuid, integer)': 'dog_work',
  'app.work_stats(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_profile(app.work_stat)': { owner: 'dog_work', callers: '' },
  'app.work_integrity()': { owner: 'dog_work', callers: '' },
  'app.work_brake_check(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_approve_as(uuid, text, text)': { owner: 'dog_work', callers: '' },
  'app.work_party(uuid, uuid)': { owner: 'dog_work', callers: '' },
  'app.work_reverse(uuid, text, text)': { owner: 'dog_work', callers: '' },
  'app.work_who()': { owner: 'dog_work', callers: '' },
  'app.work_cap(uuid, uuid, text, boolean)': { owner: 'dog_work', callers: '' },
  'app.work_display(uuid, uuid, text)': { owner: 'dog_work', callers: '' },
  'app.work_facts(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_confirmed_size(uuid, text)': { owner: 'dog_work', callers: '' },
  'app.work_finish(uuid, text, text, integer, text)': { owner: 'dog_work', callers: '' },
  'app.work_jevs_run(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_card(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_anchored_through()': { owner: 'dog_work', callers: '' },
  'app.work_project_card(uuid)': { owner: 'dog_work', callers: '' },
  'app.work_record(uuid, uuid, text, uuid, uuid, text, text, text, text, text, integer, text, integer)': { owner: 'dog_work', callers: '' },
  'app.log_work(text, text, text, text, jsonb)': { owner: 'dog_log', callers: 'dog_work' },
  'app.log_work_name(text)': { owner: 'dog_log', callers: '' },
  // 056, the trust Engine's steps E1 to E3 (design/engine-e1-e3.md), as dog_work: the page's two public reads; an
  // agent's forecast; an administrator's precedents, findings and fixes; an owner's work orders and their resumes. Each
  // write checks who is acting. Inside them, called by none of them directly: the one writer of licenses, a forecast's
  // resolution, a work order's state and its watch, the agent as the pages show it, the daily alert; and the three
  // triggers after the work module's submissions, points and claims change, which never refuse the change.
  'app.engine_summary()': 'dog_work',
  'app.engine_agent(uuid)': 'dog_work',
  'app.engine_forecast(uuid, integer, jsonb, boolean)': 'dog_work',
  'app.engine_precedent_add(text, text, text, text, uuid)': 'dog_work',
  'app.engine_finding_add(uuid, text, text, boolean, text)': 'dog_work',
  'app.engine_finding_fix(uuid, text)': 'dog_work',
  'app.engine_order_add(uuid, uuid, integer, integer, integer, text)': 'dog_work',
  'app.engine_order_resume(uuid, integer, integer)': 'dog_work',
  'app.engine_license_refresh(uuid, uuid)': { owner: 'dog_work', callers: '' },
  'app.engine_forecast_settle(uuid, text, uuid)': { owner: 'dog_work', callers: '' },
  'app.engine_order_state(uuid)': { owner: 'dog_work', callers: '' },
  'app.engine_order_watch(uuid)': { owner: 'dog_work', callers: '' },
  'app.engine_agent_card(uuid)': { owner: 'dog_work', callers: '' },
  'app.engine_trouble(text)': { owner: 'dog_work', callers: '' },
  'app.engine_on_submission()': { owner: 'dog_work', callers: '' },
  'app.engine_on_points()': { owner: 'dog_work', callers: '' },
  'app.engine_on_claim()': { owner: 'dog_work', callers: '' },
  'app.engine_claim_cap()': { owner: 'dog_work', callers: '' }
};
const NO_UUID_PK = ['app.schema_migrations', 'app.runner_tokens']; // bookkeeping keyed by file name or token ID, not a record

// The audit log's reviewed policies, compared with spaces and brackets removed so Postgres versions that print
// them slightly differently still match. Since 020 each call of who is acting is a sub-select, "(SELECT app.actor_kind()
// AS actor_kind)", run once per query; test/policy-initplan.test.js proves 020 changed nothing else.
const AUDIT_POLICIES = {
  audit_insert: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_select: { cmd: 'r', using: "SELECTapp.actor_kind()ASactor_kind='admin'::text", check: '' },
  audit_insert_signin: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_erase: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_delegate: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_jevs: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  audit_insert_owner: { cmd: 'a', using: '', check: "actor_kind=SELECTapp.actor_kind()ASactor_kindANDNOTactor_idISDISTINCTFROMSELECTapp.current_actor_id()AScurrent_actor_id" },
  // 030 (the CSO's review, S1): restrictive, so it only narrows the ones above. The site's roles can't record the two
  // actions the behaviour watch turns into alerts on its own (a new administrator, a JEVs setting changed).
  audit_insert_not_watched: { cmd: 'a', using: '', check: "action<>ALLARRAY['admin.set'::text,'jevs.setting'::text]", permissive: false,
    roles: 'dog_app,dog_delegate,dog_erase,dog_signin' },
  // 032 (guardrails round 1): JEVs reads the promotion records only, for the never-break rule "every administrator was
  // made one through a recorded promotion" (app.invariants_check); the columns it may read are action, subject_kind
  // and subject_id, never who did it or the detail.
  audit_jevs_select: { cmd: 'r', using: "action='admin.set'::text", check: '', roles: 'dog_jevs' },
  // 051 (the administrator's console): the work module's role records each console read, as the one acting, and reads
  // only the rows the console's admins tab shows (administrators' actions, console reads, promotions, sign-ins).
  audit_insert_console: { cmd: 'a', using: '', check: "((( SELECT app.actor_kind() AS actor_kind) = 'admin'::text) AND (action = 'console.read'::text) AND (actor_kind = ( SELECT app.actor_kind() AS actor_kind)) AND (NOT (actor_id IS DISTINCT FROM ( SELECT app.current_actor_id() AS current_actor_id))))", roles: 'dog_work' },
  audit_select_console: { cmd: 'r', using: "((( SELECT app.actor_kind() AS actor_kind) = 'admin'::text) AND ((actor_kind = 'admin'::text) OR (action = ANY (ARRAY['console.read'::text, 'admin.set'::text])) OR ((action = 'member.signed_in'::text) AND (subject_kind = 'member'::text) AND (subject_id IN ( SELECT m.id FROM app.members m WHERE m.is_admin)))))", check: '', roles: 'dog_work' }
};
const squash = (s) => (s || '').replace(/[\s()]/g, '');

async function problems(sql, { snapshot } = {}) {
  const out = [];
  const add = (s) => out.push(s);

  // ---- Everything security-relevant matches the reviewed snapshot (db/snapshot.txt) ----
  if (snapshot) {
    const now = await fingerprint(sql);
    const want = new Set(snapshot), have = new Set(now);
    for (const line of now) if (!want.has(line)) add('not in the reviewed snapshot: ' + line + ' (S1, S7)');
    for (const line of snapshot) if (!have.has(line)) add('missing compared with the reviewed snapshot: ' + line + ' (S1, S7)');
  }

  // ---- Tables, views and policies (S1) ----
  const rels = await sql`
    select n.nspname as schema, c.relname as name, c.relkind as kind, c.relrowsecurity as rls,
           c.relforcerowsecurity as forced, c.reloptions as options, pg_get_userbyid(c.relowner) as owner
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p', 'v', 'm', 'f')`;
  for (const t of rels) {
    const name = t.schema + '.' + t.name;
    if (t.schema === 'public') add(name + ' is in the public schema; our tables belong in app (S1)');
    if (t.owner !== 'dog_owner') add(name + ' is owned by ' + t.owner + '; everything in app belongs to dog_owner (S1)');
    if (t.kind === 'r' || t.kind === 'p') {
      if (!t.rls) add(name + ' does not have row-level security on (S1)');
      if (!t.forced) add(name + ' does not have row-level security forced (S1)');
    }
    if (t.kind === 'v' && !(t.options || []).includes('security_invoker=true')) add(name + ' is a view without security_invoker, so it would skip row-level security (S1)');
    if (t.kind === 'm') add(name + ' is a materialized view, which row-level security cannot cover (S1)');
    if (t.kind === 'f') add(name + ' is a foreign table, which row-level security cannot cover (S1)');
  }

  // One permissive policy per action (a policy "for all" counts for every action): a second one would widen the
  // first without anyone editing it.
  const pol = await sql`
    select n.nspname || '.' || c.relname as tbl, p.polname as name, p.polcmd as cmd, p.polpermissive as permissive,
           coalesce((select array_agg(case when r = 0 then 'PUBLIC' else pg_get_userbyid(r) end) from unnest(p.polroles) r), '{}') as roles,
           pg_get_expr(p.polqual, p.polrelid) as using, pg_get_expr(p.polwithcheck, p.polrelid) as check
    from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner'`;
  const perms = {};
  for (const p of pol.filter((x) => x.permissive)) {
    for (const role of p.roles) for (const cmd of p.cmd === '*' ? ['r', 'a', 'w', 'd'] : [p.cmd]) {
      const k = p.tbl + ' ' + cmd + ' ' + role;
      (perms[k] = perms[k] || []).push(p.name);
    }
  }
  for (const p of pol) if (p.roles.includes('PUBLIC')) add(p.tbl + ' policy ' + p.name + ' applies to every role; name the role (S1)');
  for (const [k, names] of Object.entries(perms)) if (names.length > 1) add(k.split(' ')[0] + ' has ' + names.length + ' permissive policies for one action and role (' + names.join(', ') + '); combine them into one (S1)');

  const audit = pol.filter((p) => p.tbl === 'app.audit_log');
  const auditNames = audit.map((p) => p.name).sort();
  if (auditNames.join() !== Object.keys(AUDIT_POLICIES).sort().join()) add('the audit log has policies ' + (auditNames.join(', ') || 'none') + '; it must have exactly ' + Object.keys(AUDIT_POLICIES).sort().join(', ') + ' (S7)');
  for (const p of audit) {
    const want = AUDIT_POLICIES[p.name];
    if (want && (p.cmd !== want.cmd || p.permissive !== (want.permissive !== false) || squash(p.using) !== squash(want.using)
        || squash(p.check) !== squash(want.check) || (want.roles && [...p.roles].sort().join() !== want.roles))) {
      add('the audit log policy ' + p.name + ' differs from the reviewed one (S7)');
    }
  }

  // ---- Rights (S1, S7) ----
  const grants = await sql`
    select n.nspname || '.' || c.relname as name, coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    left join pg_roles r on r.oid = a.grantee
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p', 'v')
      and coalesce(r.rolname, 'PUBLIC') not in ('dog_owner', 'dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs', 'dog_timers', 'dog_log', 'dog_work')`;
  for (const g of grants) add(g.name + ' grants ' + g.privilege + ' to ' + g.grantee + '; only dog_owner, dog_app and the narrow roles may hold rights (S1)');
  // dog_signin's rights are pinned exactly by the reviewed snapshot; it holds none on the tables of later features.

  // Anywhere outside app: the acting roles may not write, and nothing may be granted to them by name.
  for (const role of ACTING) {
    const outside = await sql`
      select n.nspname || '.' || c.relname as name
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname not in ('app', 'pg_catalog', 'information_schema') and n.nspname !~ '^pg_toast'
        and c.relkind in ('r', 'p', 'v', 'm', 'f')
        and exists (select 1 from pg_roles where rolname = ${role})
        and (has_table_privilege(${role}, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
             or has_any_column_privilege(${role}, c.oid, 'INSERT, UPDATE')
             or exists (select 1 from aclexplode(c.relacl) a where a.grantee = (select oid from pg_roles where rolname = ${role}))
             -- Reading through PUBLIC counts too, where the role can use the schema; providers' own schemas that
             -- every role may read (Supabase's "extensions") are left out.
             or (has_schema_privilege(${role}, n.oid, 'USAGE') and n.nspname not in ('extensions')
                 and has_any_column_privilege(${role}, c.oid, 'SELECT')))`;
    for (const o of outside) add(role + ' can reach ' + o.name + ' outside the app schema, where no policy protects it (S1)');
    const schemas = await sql`
      select n.nspname as name from pg_namespace n
      where exists (select 1 from pg_roles where rolname = ${role}) and has_schema_privilege(${role}, n.oid, 'CREATE')`;
    for (const x of schemas) add(role + ' can create objects in schema ' + x.name + '; it must not (S1, S7)');
    const [temp] = await sql`select exists (select 1 from pg_roles where rolname = ${role}) and has_database_privilege(${role}, current_database(), 'TEMP') as yes`;
    if (temp.yes) add(role + ' can make temporary tables, which outlive a transaction on a pooled connection (S1)');
  }
  const appSchema = await sql`
    select coalesce(r.rolname, 'PUBLIC') as grantee, a.privilege_type as privilege
    from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
    left join pg_roles r on r.oid = a.grantee
    where n.nspname = 'app' and coalesce(r.rolname, '') <> 'dog_owner'
      and not (coalesce(r.rolname, '') in ('dog_app', 'dog_signin', 'dog_public', 'dog_limits', 'dog_erase', 'dog_delegate', 'dog_jevs', 'dog_log', 'dog_work', 'dog_ghsync',
                                         'dog_witness') and a.privilege_type = 'USAGE')`;
  for (const g of appSchema) add('schema app grants ' + g.privilege + ' to ' + g.grantee + '; the acting roles may only use it (S1)');

  // The audit log: read the table, write only the four content columns.
  const [ar] = await sql`
    select has_table_privilege('dog_app', 'app.audit_log', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER') as table_write,
           has_any_column_privilege('dog_app', 'app.audit_log', 'UPDATE') as column_update,
           (select array_agg(a.attname::text order by a.attname) from pg_attribute a
            where a.attrelid = 'app.audit_log'::regclass and a.attnum > 0 and not a.attisdropped
              and has_column_privilege('dog_app', 'app.audit_log', a.attnum, 'INSERT')) as insertable`;
  if (ar.table_write || ar.column_update) add('dog_app holds more rights on the audit log than reading and adding rows (S7)');
  if ((ar.insertable || []).join() !== 'action,detail,subject_id,subject_kind') add('dog_app can set audit log columns ' + (ar.insertable || []).join(', ') + '; only action, subject_kind, subject_id and detail (S7)');

  // ---- Roles (S1, S7) ----
  // Memberships that pass on rights. From Postgres 16, whoever creates a role is given an admin-only membership in
  // it that passes on nothing (no SET, no INHERIT), so those are left out; Postgres 15 has no such memberships.
  const [{ v }] = await sql`select current_setting('server_version_num')::int as v`;
  const roles = v >= 160000 ? await sql`
    with m as (select roleid, member from pg_auth_members where set_option or inherit_option)
    select r.rolname as name, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication,
           coalesce((select array_agg(distinct g.rolname::text) from m join pg_roles g on g.oid = m.roleid where m.member = r.oid), '{}') as member_of,
           r.oid in (select m.member from m where m.roleid = (select oid from pg_roles where rolname = 'dog_app')) as uses_app
    from pg_roles r` : await sql`
    with m as (select roleid, member from pg_auth_members)
    select r.rolname as name, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication,
           coalesce((select array_agg(distinct g.rolname::text) from m join pg_roles g on g.oid = m.roleid where m.member = r.oid), '{}') as member_of,
           r.oid in (select m.member from m where m.roleid = (select oid from pg_roles where rolname = 'dog_app')) as uses_app
    from pg_roles r`;
  const app = roles.find((r) => r.name === 'dog_app');
  const owner = roles.find((r) => r.name === 'dog_owner');
  if (!app || !owner || NARROW.some((n) => !roles.find((r) => r.name === n))) add('the dog_app, dog_owner, ' + NARROW.join(', ') + ' roles must all exist (S1)');
  const powers = [['rolsuper', 'superuser'], ['rolbypassrls', 'bypass row-level security'], ['rolcreaterole', 'create roles'],
    ['rolcreatedb', 'create databases'], ['rolreplication', 'replication']];
  if (app) {
    for (const [k, label] of powers.concat([['rolcanlogin', 'sign in directly']])) if (app[k]) add('dog_app can ' + label + '; it must not (S1, S7)');
    if (app.member_of.length) add('dog_app belongs to ' + app.member_of.join(', ') + '; it must belong to no role, or it gains that role\'s rights (S1, S7)');
  }
  for (const name of NARROW) {
    const r = roles.find((x) => x.name === name);
    if (!r) continue;
    for (const [k, label] of powers.concat([['rolcanlogin', 'sign in directly']])) if (r[k]) add(name + ' can ' + label + '; it must not (S1)');
    if (r.member_of.length) add(name + ' belongs to ' + r.member_of.join(', ') + '; it must belong to no role (S1)');
    const holders = roles.filter((x) => x.member_of.includes(name) && x.name !== 'dog_owner').map((x) => x.name);
    if (holders.length) add(holders.join(', ') + ' can act as ' + name + '; only dog_owner may, to hand it its functions (S1)');
  }
  if (owner) for (const [k, label] of [['rolsuper', 'superuser'], ['rolbypassrls', 'bypass row-level security'], ['rolcanlogin', 'sign in directly']]) {
    if (owner[k]) add('dog_owner can ' + label + '; it must not (S1)');
  }
  // The login the site uses: switching to dog_app is the only thing it can do.
  for (const r of roles.filter((x) => x.uses_app)) {
    for (const [k, label] of powers) if (r[k]) add(r.name + ' (which the site signs in as) can ' + label + '; it must not (S1)');
    const other = r.member_of.filter((g) => g !== 'dog_app');
    if (other.length) add(r.name + ' (which the site signs in as) also belongs to ' + other.join(', ') + '; it may belong only to dog_app (S1, S7)');
  }
  for (const role of ACTING) {
    const owned = await sql`select count(*)::int as n from pg_class where relowner = (select oid from pg_roles where rolname = ${role})`;
    if (owned[0].n) add(role + ' owns ' + owned[0].n + ' tables or other objects; an owner can switch off policies and triggers (S7)');
  }
  // 027: the timers' role may make the site's own stamp, so it must stay exactly as narrow as it was made.
  const timers = roles.find((r) => r.name === TIMERS);
  if (!timers) add('the ' + TIMERS + ' role must exist (027)');
  else {
    for (const [k, label] of powers.concat([['rolcanlogin', 'sign in directly']])) if (timers[k]) add(TIMERS + ' can ' + label + '; it must not (027)');
    if (timers.member_of.join() !== 'dog_app') add(TIMERS + ' belongs to ' + (timers.member_of.join(', ') || 'no role') + '; it must belong to dog_app only (027)');
    // Memberships that pass on rights (SET or INHERIT), so the creator's ADMIN-only membership (Postgres 16 and later; on
    // Supabase, the runner's postgres login) is left out, while a membership it later grants itself is caught (N4).
    const holders = roles.filter((x) => x.member_of.includes(TIMERS)).map((x) => x.name);
    if (holders.length) add(holders.join(', ') + ' can act as ' + TIMERS + '; no role may (027)');
    const [own] = await sql`select coalesce(array_agg(p.oid::regprocedure::text order by 1), '{}') as fns from pg_proc p
                            where p.proowner = (select oid from pg_roles where rolname = ${TIMERS})`;
    if (own.fns.join() !== 'app.timers_run(boolean)') add(TIMERS + ' owns ' + (own.fns.join(', ') || 'nothing') + '; it must own app.timers_run(boolean) only (027)');
  }

  // ---- Functions (S1) ----
  const fns = await sql`
    select n.nspname || '.' || p.proname as name, n.nspname || '.' || p.proname || '(' || oidvectortypes(p.proargtypes) || ')' as signature,
           p.prosecdef as definer, pg_get_userbyid(p.proowner) as owner,
           coalesce(array_to_string(p.proconfig, ';'), '') as config,
           coalesce((select array_agg(case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end order by 1)
                     from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                     where a.privilege_type = 'EXECUTE' and a.grantee <> p.proowner), '{}') as callers
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner'`;
  for (const f of fns) {
    if (f.callers.includes('PUBLIC')) add(f.name + ' can be called by every role; grant it to dog_app only (S1)');
    if (f.definer) {
      if (!Object.hasOwn(DEFINERS, f.signature)) add(f.signature + ' runs with its owner\'s rights (security definer); not allowed without a reviewed exception (S1)');
      else {
        const want = typeof DEFINERS[f.signature] === 'string' ? { owner: DEFINERS[f.signature], callers: 'dog_app' } : DEFINERS[f.signature];
        if (f.owner !== want.owner) add(f.name + ' must be owned by ' + want.owner + ', not ' + f.owner + ' (S1)');
        if (f.config !== 'search_path=pg_catalog') add(f.name + ' must fix its search path to pg_catalog (S1)');
        if ([...f.callers].sort().join() !== want.callers) add(f.name + ' may be called only by ' + want.callers + ', not ' + (f.callers.join(', ') || 'nobody') + ' (S1)');
      }
    } else if (f.owner !== 'dog_owner') add(f.name + ' is owned by ' + f.owner + '; everything in app belongs to dog_owner (S1)');
  }

  // ---- The guard triggers (S3, S7, G4) ----
  // tgtype bits: 1 = once per row, 2 = before, 8 = delete, 16 = update, 32 = truncate. "A" = fires always, even in
  // replication mode. No WHEN condition, arguments or column list, which could hide an off-switch.
  const trig = await sql`
    select c.relname as tbl, t.tgname as name, t.tgtype as type, t.tgenabled as enabled, p.proname as fn, p.prosrc as src,
           t.tgqual is null and t.tgnargs = 0 and coalesce(array_length(t.tgattr::int2[], 1), 0) = 0 as plain
    from pg_trigger t join pg_proc p on p.oid = t.tgfoid join pg_class c on c.oid = t.tgrelid
    where c.relnamespace = 'app'::regnamespace and not t.tgisinternal`;
  for (const [tbl, name, type, fn, what] of [
    ['audit_log', 'audit_log_no_change', 26, 'audit_log_append_only', 'every update and delete statement'],
    ['audit_log', 'audit_log_no_truncate', 34, 'audit_log_append_only', 'every truncate statement'],
    ['members', 'members_guard', 19, 'members_guard', 'every updated member row'],
    // PR 4: only a reviewer changes a post's status, along the allowed moves; flags close once, in the reviewer's name.
    ['posts', 'posts_review_guard', 19, 'posts_review_guard', 'every updated post row'],
    ['review_flags', 'review_flags_guard', 19, 'review_flags_guard', 'every updated flag row'],
    // PR 5: an agent's owner never changes and revoking is final; keys only get revoked.
    ['agents', 'agents_guard', 19, 'agents_guard', 'every updated agent row'],
    ['agent_keys', 'agent_keys_guard', 19, 'agent_keys_guard', 'every updated key row'],
    // PR 6: a brake is only ever switched off, once; the brake checks run before every new post and new agent.
    ['brakes', 'brakes_guard', 19, 'brakes_guard', 'every updated brake row'],
    ['posts', 'posts_limit', 7, 'posts_limit', 'every new post'],
    ['agents', 'agents_limit', 23, 'agents_limit', 'every new or updated agent row'],
    // PR 7: rules versions are only added; a draft's words never change and it is decided once; agent posts follow the rules.
    ['agent_rules', 'agent_rules_guard', 27, 'agent_rules_guard', 'every updated or deleted rules row'],
    ['agent_rules', 'agent_rules_fill', 7, 'agent_rules_fill', 'every new rules version'],
    ['agent_drafts', 'agent_drafts_guard', 19, 'agent_drafts_guard', 'every updated draft'],
    ['agent_drafts', 'agent_drafts_fill', 7, 'agent_drafts_fill', 'every new draft'],
    ['posts', 'posts_delegation', 7, 'posts_delegation', 'every new post'],
    // PR 12: JEVs decisions are only added; a challenge is answered once, by JEVs; settings keep their names and ranges.
    ['jevs_decisions', 'jevs_decisions_guard', 27, 'jevs_decisions_guard', 'every updated or deleted decision'],
    ['jevs_challenges', 'jevs_challenges_guard', 27, 'jevs_challenges_guard', 'every updated or deleted challenge'],
    ['jevs_settings', 'jevs_settings_check', 23, 'jevs_settings_check', 'every new or changed setting'],
    // A deletion review's subject never changes; only Aaron's decision or the 24-hour timer moves it.
    ['deletion_reviews', 'deletion_reviews_guard', 27, 'deletion_reviews_guard', 'every updated or deleted deletion review'],
    // PR 16: a parent's daily cap counts its whole subtree, before every new post and draft.
    ['posts', 'posts_tree_cap', 7, 'agent_tree_cap', 'every new post'],
    ['agent_drafts', 'agent_drafts_tree_cap', 7, 'agent_tree_cap', 'every new draft'],
    // 056, the trust Engine (Rev 4.2): a license's history is only added to; a forecast is fixed but for its one
    // resolution; a precedent is never edited; a finding only gets its fix, once, from the Engine's own function; a
    // work order and its resumes never change. Each goes only with what it belongs to (an agent's account, a claim).
    ['engine_license_history', 'engine_license_history_guard', 27, 'engine_history_guard', 'every updated or deleted license change'],
    ['engine_forecasts', 'engine_forecasts_guard', 27, 'engine_forecasts_guard', 'every updated or deleted forecast'],
    ['engine_citations', 'engine_citations_guard', 27, 'engine_citations_guard', 'every updated or deleted citation'],
    ['engine_precedents', 'engine_precedents_guard', 27, 'engine_precedents_guard', 'every updated or deleted precedent'],
    ['engine_findings', 'engine_findings_guard', 27, 'engine_findings_guard', 'every updated or deleted finding'],
    ['engine_orders', 'engine_orders_guard', 27, 'engine_orders_guard', 'every updated or deleted work order'],
    ['engine_order_resumes', 'engine_order_resumes_guard', 27, 'engine_resumes_guard', 'every updated or deleted resume']
  ]) {
    const t = trig.find((x) => x.tbl === tbl && x.name === name);
    const label = 'the app.' + tbl + ' trigger ' + name;
    if (!t) { add('app.' + tbl + ' is missing its ' + name + ' trigger (S3, S7)'); continue; }
    if (t.enabled !== 'A') add(label + ' is not set to fire always (S3, S7)');
    if (t.type !== type || !t.plain) add(label + ' no longer runs before ' + what + ' without conditions (S3, S7)');
    if (t.fn !== fn || !/raise\s+exception/i.test(t.src) || (fn === 'audit_log_append_only' && /\breturn\b/i.test(t.src))) add(label + ' no longer refuses the change (S3, S7)');
  }
  // RK82 (021): the sign-in level cap. These lower a level instead of refusing, so they are checked by their own rule:
  // present, firing always, before every new (or, for methods, re-levelled) row, and still capping at 1.
  for (const [tbl, name, type] of [['identities', 'identities_level_cap', 23], ['members', 'members_level_cap', 7]]) {
    const t = trig.find((x) => x.tbl === tbl && x.name === name);
    const label = 'the app.' + tbl + ' trigger ' + name;
    if (!t) { add('app.' + tbl + ' is missing its ' + name + ' trigger (RK82)'); continue; }
    if (t.enabled !== 'A') add(label + ' is not set to fire always (RK82)');
    if (t.type !== type || t.fn !== name || !/cap constant smallint := 1;/.test(t.src)) add(label + ' no longer caps sign-in levels at 1 (RK82)');
  }

  // ---- Columns and keys (S8, S12, G3) ----
  const seqs = await sql`
    select n.nspname || '.' || c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind = 'S'`;
  for (const s of seqs) add(s.name + ' is a counter; IDs must be UUIDv7 (G3)');

  const cols = await sql`
    select n.nspname || '.' || c.relname as tbl, a.attname as col, format_type(a.atttypid, a.atttypmod) as type,
           t.typlen as len, t.typcategory as category, a.atttypmod as typmod, a.attidentity as identity,
           pg_get_expr(d.adbin, d.adrelid) as def,
           exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'p' and a.attnum = any (k.conkey)) as pk,
           exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'f' and a.attnum = any (k.conkey)) as fk,
           coalesce((select array_agg(pg_get_constraintdef(k.oid)) from pg_constraint k
                     where k.conrelid = c.oid and k.contype = 'c' and a.attnum = any (k.conkey)), '{}') as checks
    from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
    join pg_type t on t.oid = a.atttypid
    left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner')
      and c.relkind in ('r', 'p') and a.attnum > 0 and not a.attisdropped`;
  for (const c of cols) {
    const name = c.tbl + '.' + c.col;
    if (c.category === 'A') add(name + ' is an array; use a table so each item has its own size limit (S8)');
    else if (c.len === -1 && c.category !== 'N' && !limited(c)) add(name + ' has no size limit (S8)');
    if (c.identity) add(name + ' is an identity counter; IDs must be UUIDv7 (G3)');
    if (c.def && /nextval\(/.test(c.def)) add(name + ' takes its value from a counter; IDs must be UUIDv7 (G3)');
    if ((c.pk && !NO_UUID_PK.includes(c.tbl)) || c.col === 'id') {
      if (c.type !== 'uuid' || c.def !== 'app.uuid_v7()') add(name + ' is a key and must be a uuid with default app.uuid_v7() (G3)');
    }
    if (c.fk && c.type !== 'uuid') add(name + ' points at another record and must be a uuid (G3)');
    if (FORBIDDEN_COLUMN.test(c.col)) add(name + ' looks like it stores an ID document, ID number, face image or password (S5, S12)');
  }

  return out;
}

// A column is limited by varchar(n), or by a check constraint built only from AND, one of whose parts is exactly
// a cap of MAX_LIMIT or less on the column's length, or a fixed list of values. OR, NOT, CASE, IS and the like
// are refused, because they can make a cap that never binds.
const ESCAPES = /\b(OR|NOT|CASE|IS|COALESCE|NULLIF|GREATEST|LEAST)\b|<>|!=|=\s*(true|false)\b/i;
function limited(c) {
  const m = c.type.match(/^character varying\((\d+)\)$/);
  if (m && Number(m[1]) <= MAX_LIMIT) return true;
  const col = c.col.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const cap = new RegExp('^\\(*(char_length|octet_length)\\(+' + col + '\\)*(::text\\)*)?\\s*(<|<=|=)\\s*(\\d+)\\)*$');
  const list = new RegExp('^\\(*' + col + '\\s*=\\s*ANY\\s*\\(+ARRAY\\[[^\\]]*\\]\\)*$');
  return c.checks.some((def) => {
    const body = def.replace(/^CHECK\s*/i, '');
    if (ESCAPES.test(body)) return false;
    return body.split(/\s+AND\s+/i).map((part) => part.trim()).some((part) => {
      if (list.test(part)) return true;
      const x = part.match(cap);
      return x !== null && Number(x[4]) <= MAX_LIMIT;
    });
  });
}

// A plain-text record of every security-relevant setting in our schemas: policies, rights (table and column),
// column defaults, check constraints, triggers (with their on/off state) and functions (their attributes and a
// hash of their body). db/snapshot.txt holds the reviewed version, rebuilt from the migrations with
// `npm run db:snapshot`; a pull request that changes it shows exactly what changed, line by line.
async function fingerprint(sql) {
  const rows = await sql`
    with ours as (
      select c.oid, n.nspname || '.' || c.relname as tbl from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and c.relkind in ('r', 'p', 'v', 'm', 'f')
    )
    select 'policy ' || o.tbl || ' ' || p.polname || ' cmd=' || p.polcmd::text || ' permissive=' || p.polpermissive::text
           || ' to=' || coalesce((select string_agg(case when r = 0 then 'PUBLIC' else pg_get_userbyid(r) end, ',' order by 1) from unnest(p.polroles) r), '')
           || ' using=' || coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' check=' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as line
    from pg_policy p join ours o on o.oid = p.polrelid
    union all
    select 'grant ' || o.tbl || ' ' || case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end || ' ' || a.privilege_type
    from ours o join pg_class c on c.oid = o.oid cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    -- The owner's own rights are left out: an owner always holds all of them, and the list differs by version.
    where a.grantee <> c.relowner
    union all
    select 'grant ' || o.tbl || '.' || at.attname || ' ' || case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end || ' ' || a.privilege_type
    from ours o join pg_attribute at on at.attrelid = o.oid cross join lateral aclexplode(at.attacl) a
    where at.attnum > 0 and not at.attisdropped and at.attacl is not null
    union all
    select 'default ' || o.tbl || '.' || at.attname || ' = ' || pg_get_expr(d.adbin, d.adrelid)
    from ours o join pg_attribute at on at.attrelid = o.oid join pg_attrdef d on d.adrelid = at.attrelid and d.adnum = at.attnum
    union all
    select 'constraint ' || o.tbl || ' ' || k.conname || ' ' || pg_get_constraintdef(k.oid)
    from ours o join pg_constraint k on k.conrelid = o.oid
    union all
    select 'trigger ' || o.tbl || ' enabled=' || t.tgenabled::text || ' ' || pg_get_triggerdef(t.oid)
    from ours o join pg_trigger t on t.tgrelid = o.oid where not t.tgisinternal
    union all
    select 'function ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') owner='
           || pg_get_userbyid(p.proowner) || ' execute=' || coalesce((select string_agg(case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end, ',' order by 1)
             from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a where a.privilege_type = 'EXECUTE'), '')
           || ' language=' || l.lanname || ' volatile=' || p.provolatile::text || ' definer=' || p.prosecdef::text
           || ' config=' || coalesce(array_to_string(p.proconfig, ';'), '') || ' returns=' || pg_get_function_result(p.oid)
           || ' body_md5=' || md5(p.prosrc)
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
    where (n.nspname in ('app', 'public') or pg_get_userbyid(n.nspowner) = 'dog_owner') and p.prokind in ('f', 'p')`;
  // One space between words, so the same definition reads the same on every Postgres version.
  return [...new Set(rows.map((r) => r.line.replace(/\s+/g, ' ').trim()))].sort();
}

module.exports = { problems, fingerprint, limited, MAX_LIMIT };
