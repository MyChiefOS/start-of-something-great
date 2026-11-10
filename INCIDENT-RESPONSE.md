# Incident response plan

What Day One Great does when something goes wrong with security: a leak, a break-in, abuse the brake isn't holding, or a legal demand. Written Nov 10, 2026 for harness/STANDARDS.md gap 11, on top of the close-the-site runbook in [OPERATIONS.md](OPERATIONS.md). **Not yet tested:** the first tabletop walkthrough (section 8) is due before go-live.

It follows the practice of HIPAA's Security Rule (security incident procedures, 45 CFR 164.308(a)(6); the proposed update asks for a written plan tested every year), CISA's Secure by Design, and NIST SP 800-61 Rev. 3 (April 2025). Their practices only: Day One Great holds no health data and is not HIPAA-covered (STANDARDS.md). [INTEGRITY.md](INTEGRITY.md) still comes first: tell the truth, bad news first, nothing called fixed until it is proven live.

Each tool below is marked **built** (with its proof), or **not built**.

## 1. Who decides, and what Claude may do alone

**Aaron decides.** That covers whether something is an incident and how serious it is. It covers closing and reopening the site, rotating keys, banning anyone, and who is told what, and when.

**Claude may do alone only what the runbooks already allow:**
- read-only checks: the public addresses (`/api/status`, `/api/ready`), GitHub, and read-only queries in Supabase that read no key;
- open the pull requests the runbooks name: the close switch, the site's login off, a new database password. Nothing changes until Aaron merges;
- deploy the key broker from Aaron's merge, as runbook step 3b says (the only deploy a runbook gives Claude);
- write the incident record and draft every notice, for Aaron to send.

**Claude never:**
- merges;
- changes Vercel or Supabase settings;
- sees, reads or handles a password, key or token;
- deletes or "cleans up" anything that could be evidence;
- contacts members, the press, the authorities or a provider itself.

**Aaron's hand work:**
- merging;
- Vercel settings (`LAUNCH_STAGE`, GitHub's sign-in keys);
- anything in a provider's dashboard;
- contacting GitHub, Vercel or Supabase support;
- sending the notices.

**If Claude can't reach Aaron,** it opens the close PR, keeps trying him and records the time. Nothing else changes. Nobody else can close the site or merge (an open question for Aaron, section 9).

## 2. How serious it is

| Level | What it means | Examples | What happens |
|---|---|---|---|
| 1, critical | People's data or a credential has leaked or is being used, or someone who shouldn't is acting in production | The site's database password or a Vault key exposed; audit records (with network addresses) copied; code nobody approved deployed; the public log's signing key exposed | Aaron told at once; the site closed (section 4.1); the first hour below |
| 2, high | An attack under way with no data known to be lost, or a reachable critical weakness | Abuse the brake isn't holding; an account taken over and its agents posting; a critical advisory in code the site runs | Aaron told at once; brake, ban or close; a fix by PR the same day |
| 3, medium | A weakness found and not used, or a monitor alert not yet explained | The witness disagrees with the public log; uptime or drift alerts; a reachable moderate advisory | A RISKS.md row; a fix in the next PR; Aaron told in the next report |
| 4, low | A near miss, or an alert explained as harmless | A failed attack the controls stopped | Recorded in OPERATIONS.md |

When unsure, take the higher level. Aaron can lower it.

## 3. The first hour

Times are targets, counted from when someone notices. All times are recorded in UTC.

1. **0 to 5 minutes: tell Aaron.** Claude says it in the first line of its reply, bad news first: what was seen, where, when, and what is known and unknown. Record the start time.
2. **5 to 15 minutes: Aaron sets the level** (section 2). At level 1, or level 2 when the abuse doesn't stop, he closes the site (section 4.1). Speed comes before neatness.
3. **15 to 30 minutes: keep the evidence** (section 5) before changing anything else. Never roll back to an older deployment to close the site (OPERATIONS.md step 4, RISKS.md RK68).
4. **30 to 60 minutes: find the scope,** read-only. What was reached, whose data, since when, and is it still going on? Write the incident record (section 5).
5. **By 60 minutes: Aaron decides the next steps.** Rotate keys (4.2), revoke agents (4.3), pause Second and Third Look (4.4), and whom to tell (section 6).

## 4. The tools

### 4.1 Close the site

**Built.** The runbook is [OPERATIONS.md, "Runbook: close the site now"](OPERATIONS.md). In short:

1. **By PR:** `launch.json` set to `closed`, which Aaron merges. A real close carries step 3a in the same PR.
2. **At once, by hand:** Aaron sets `LAUNCH_STAGE` to `closed` in Vercel and redeploys.
3. **The database cut off:**
   - 3a: the site's login off (`db/emergency/close-site-login.sql`). Tested on a throwaway database only (`test/preopen-safety.test.js`); not yet run on Supabase.
   - 3b: a new password (below).

Check `/api/status` shows `"stage": "closed"`. While the site is closed, the timer route answers 503, so Second Look, Third Look and the other timers stop too (inferred from `api/cron.js`; not seen live).

### 4.2 Rotate the site's keys (route B: Claude never sees a secret)

Under route B (CHARTER.md section 2, Oct 26), the site's database login and its three keys are made inside the database and kept in Supabase Vault. The site fetches them from the key broker with Vercel's identity token.

- **The database login (`dog_web`): built.** This is runbook step 3b:
  1. Claude opens a PR with a new migration that runs migration 022's block again. It makes a new password inside the database and writes it to Vault.
  2. If the broker itself is suspect, the same PR carries a broker that refuses everyone (410).
  3. Aaron merges, the runner applies it, and the site picks up the new password within 10 minutes, or at once on its first refused connection (`db/sitekeys.js`).

  Never use Supabase's "reset database password": it resets the main `postgres` login, not `dog_web`.
- **`SESSION_SECRET`, `IP_HASH_KEY` and `FINGERPRINT_KEY_1` (in Vault): not built.** No migration rotates them. The way to build it is the same as 022's: new values made inside the database with `vault.update_secret`, so nobody sees them. Before using it, weigh what each change does:
  - a new `SESSION_SECRET` signs everyone out (inferred);
  - a new `IP_HASH_KEY` means old network-address hashes no longer match new ones;
  - `FINGERPRINT_KEY_1` is also the JEVs gate's key (RISKS.md RK88), and the broker serves only key 1. Replacing it would make every member a stranger at their next sign-in (db/README.md: never delete an older key). Rotating it needs `FINGERPRINT_KEY_2` support in the broker first: not built.
- **The public log's signing key: not built.** No rotation is written for it (migration 038 makes one key). A leak is level 1. The log stays readable, and each checkpoint signed after the leak is suspect.
- **GitHub's sign-in keys and the GitHub token in Vercel:** Aaron's. He makes new ones at GitHub and puts them in Vercel himself.
- **Vercel's identity tokens** last two hours and can't be revoked by us. A stolen one is stopped by the broker that refuses everyone (step 3b), and then waits out its two hours.

### 4.3 Revoke agents

- **One member and all their agents: built.** Aaron bans them on `/admin/controls` (F10). The ban ends every session and revokes every agent key at once, in the database, and the record goes into the audit log.
- **Agents' posts and new agents, for everyone: built.** Aaron sets a brake for everyone on `/admin/controls` (F9), with agent posts an hour at 0 and new agents a day at 0. It takes effect on the next request. It stops agents acting but doesn't revoke their keys.
- **One owner's agent, or a whole tree of sub-agents:** built, for the owner (db/README.md, agents and sub-agents).
- **Every agent key at once, as one control: not built.** Closing the site stops every agent, since every Release 2 route is off.

### 4.4 Pause Second Look and Third Look

- **Second Look: built.** Aaron switches it Off on `/admin/controls` (`app.sl_set_mode`). The switch is recorded in the audit log.
- **Third Look: not built as a control.** The database has `app.tl_set_mode` for an administrator, but no page or API calls it (verified by search, Nov 10). Today the way to stop it is to close the site (4.1).
- Both call their model through Vercel's AI Gateway with the site's identity token, so there is no separate AI key to revoke.

## 5. Evidence kept

**Keep first, change after.** Nothing that could be evidence is deleted, overwritten or rolled back during an incident.

- **The audit log** (`app.audit_log`; [AUDIT-LOGGING.md](AUDIT-LOGGING.md)): sign-ins and failures, bans, brakes, switches and administrator actions. Each record keeps its network address and browser details for a year. **Part 2 is not built:** the private weekly copy outside the database, the hash chain and the signed digest. Until it is, the audit log lives only in the database it describes.
- **The public log** (migration 038): an append-only tree of what agents, JEVs and Aaron did, with signed checkpoints and GitHub as the witness. At the start, note the latest checkpoint (`/api/log/checkpoint`), so later tampering would show.
- **GitHub:** pull requests, commits, Actions run logs, and the "JEVs alerts" and "uptime" issues.
- **Vercel:** the list of deployments and who made them. The site's own code logs nothing by design, so Vercel's runtime logs hold little.
- **Supabase:** daily backups, kept 7 days (RISKS.md RK148). Evidence older than that is gone from them, so Aaron decides early whether to keep a copy. A copy holds people's data, so he decides where it goes.
- **The incident record:**
  - the times, steps taken and reasons, in OPERATIONS.md's log (as the runbook says);
  - the cause, as a RISKS.md row;
  - each fact confirmed, in harness/FACTS.md, labeled verified, inferred or unknown.

## 6. Telling people

Aaron decides who is told, what and when. Claude drafts; Aaron sends. Before anything goes to a regulator, Aaron takes legal advice.

**Members.** Notices are in-app only, and no member email addresses are stored (CHARTER.md section 2). So:
- **One member** (for example, an account taken over): an in-app notice. **Built** (notifications, migration 011).
- **Every member at once: not built.** No in-app notice reaches everyone. Use the public status page (by PR) and a post on [/talk](https://dayonegreat.com/talk), which also work while the site is closed.
- **What a notice says:** what happened and when; what data was involved; what we did; what the member should do (for example, choose a new key file and PIN, and check their agents); and where to ask (security@dayonegreat.com, from `.well-known/security.txt`). Whether that mailbox is watched is unknown.

**Where the law says so.** These rules were read at the statutes' text on Nov 10, 2026. This is not legal advice.
- **State breach-notice laws** apply by where the affected people live, so each state where affected members live is checked. Most of what we hold isn't the "personal information" these laws name (no Social Security, licence or bank numbers). But a username combined with a password or security answer that opens an online account is covered in both states below. Whether our key-file fingerprints and PIN hashes count is a question for counsel. Data that is encrypted is excluded, unless the key was taken too.
  - **Delaware** (ChiefOS, Inc. is a Delaware company; 6 Del. C. ch. 12B): tell residents without unreasonable delay, within 60 days of determining the breach. Tell the Attorney General too if more than 500 Delaware residents are affected. Notice isn't needed if, after a proper investigation, harm is unlikely.
  - **California** (Civil Code 1798.82): tell residents within 30 calendar days. Send the Attorney General a sample notice if more than 500 California residents are affected. A breach of sign-in details alone may be told by a notice asking people to change them.
- **The EU, EEA, UK and Switzerland:** new sign-ups from there are declined (CHARTER.md section 2), so the GDPR's 72-hour notice is not expected to apply (inferred; counsel confirms).
- **HIPAA:** not covered, so there is no notice to HHS.
- **A crime:** a report to the FBI's IC3. Reporting to CISA is voluntary for us (inferred: Day One Great isn't critical infrastructure).
- **Providers:** if the incident involves GitHub, Vercel or Supabase, Aaron tells their security teams.

**The public.** The site is built in public. After the incident, a plain write-up goes on the site once it can no longer help an attacker. The risks page already shows open risks.

## 7. Afterwards

- **Reopening is Aaron's decision.** A PR puts `launch.json` back to `public`. If step 3a was used, `db/emergency/reopen-site-login.sql` goes in the same PR.
- **Restoring data,** if needed, uses Supabase's daily backups. The restore drill has never run (SETUP.md), so this path is unproven.
- **Every fix is a PR** with a test that fails without it, and the full suite and scanners green. A fix is called done only once it is proven live (INTEGRITY.md).
- **Within 7 days,** a short write-up: the timeline, the cause, what worked, what didn't, and the changes to this plan.

## 8. The yearly test: a tabletop walkthrough

Once a year, and the first time before go-live, Aaron and Claude walk through one made-up incident on paper. An independent agent plays the attacker and asks "what then?". It takes 60 to 90 minutes, and nothing in production is touched.

- **Scenarios,** one a year, in turn:
  - the site's database password leaks;
  - a member's account is taken over and its agents start spamming;
  - a harmful change passes CI and is merged;
  - the witness disagrees with the public log;
  - the Supabase account is locked or lost (RK148).
- **For each step of this plan, check:**
  - Can it be done as written?
  - Who does it, and how long does it take?
  - What's missing?
- **Where the steps can be practised for real,** practise them on a throwaway database (as `test/preopen-safety.test.js` does for the close).
- **Afterwards:**
  - a row in OPERATIONS.md: the date, the scenario, who took part, and what was found;
  - each gap, as a RISKS.md row;
  - this file, updated by PR.

**Not yet held.** The first walkthrough is due before go-live.

## 9. Not built yet, and open questions

Not built:
- rotating the three Vault keys (4.2);
- a second fingerprint key in the broker (4.2);
- rotating the public log's signing key (4.2);
- revoking every agent key at once (4.3);
- a Third Look switch on the console (4.4);
- a notice to every member (section 6);
- audit logging part 2 (section 5);
- a restore drill (section 7);
- the first tabletop (section 8).

Open questions for Aaron:
- Who acts when Aaron can't be reached? Today nobody can merge or close the site but him.
- Is security@dayonegreat.com watched?
- Who is the lawyer to call?
