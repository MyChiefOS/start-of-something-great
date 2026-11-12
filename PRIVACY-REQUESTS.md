# Privacy requests: how one is carried out

The runbook for a request to know, correct or erase what Day One Great holds about a person, and for a legal hold. It carries out what [the privacy page](privacy.html) promises; it promises nothing new. Written for Aaron's check of Nov 10, 2026 (part 8 of the one large PR), answering the question open since Oct 25: "How are email erasure requests carried out?"

**Not yet used.** No privacy request has been received (verified Nov 11, 2026: production has one member, the administrator). The first real request is this runbook's first test.

## The clock

The privacy page's own times, counted from the day the email arrives at `privacy@dayonegreat.com`:

| By | What |
|---|---|
| 10 business days | Confirm we received it |
| 45 days | Answer it in full |
| 90 days | Only if we wrote to the person, inside the first 45 days, saying we need more time and why |

## Step 1: who is asking

A request is acted on only when it comes from the account it is about. We never ask for an ID document, a selfie or a password.

- **A site member** proves it by signing in. Everything in step 2 that a member can do, they do themselves on their account page, signed in. If they lost their key file or PIN, signing in with a code works as long as they control their GitHub account (`/join`).
- **Someone who only posted on GitHub** proves it by replying from that GitHub account in the welcome thread, with words we give them in our email reply (any short phrase; not a sign-in code).
- **Someone who can't do either** (they no longer control the GitHub account) can't be told apart from a stranger. We say so, and that GitHub's own account recovery is the way back. We act on nothing.
- **An authorized agent** (California): the person confirms it themselves, by one of the two ways above.

## Step 2: what is done, by kind of request

| The request | Who does it | How |
|---|---|---|
| **Delete my account** | The member | Account page, "Delete account", within 10 minutes of signing in. It removes everything listed under "Deleting your account" on the privacy page. Nothing for us to do unless our checks flag it (then it is a deletion review on Owner controls, decided within 24 hours) |
| **Erase what your checks hold about my GitHub posts** | The person, or Aaron | The person deletes their posts on GitHub; our checks erase what they kept about each post, and the account's record once no post remains. If they ask us to do it, Aaron deletes those comments on GitHub (he is the repository's owner), which sets off the same erasure. GitHub's own copies are GitHub's |
| **What do you hold about me?** | Claude, then Aaron sends it | Aaron gives Claude the member's ID (on Owner controls, the Legal hold button on their row puts it in the Member ID box) or, for someone who only posted on GitHub, their GitHub username. Claude reads production read-only and writes the answer from the tables in "Where a person's records are" below: what each holds, in plain words, with the person's own values. Aaron sends it from the privacy mailbox. Keyed hashes and fingerprints are described, not sent: they identify nobody outside our database |
| **Correct something** | The member | Their display name: account page. Their posts: delete and post again. Nothing else we hold is typed by them |
| **Delete an email I sent you** | Aaron | Delete it in the mailbox; it leaves our systems within 30 days |
| **I live in the EU, EEA, UK or Switzerland and have posted** | As "Erase what your checks hold", above | The service isn't offered there; we erase on request |

What erasing can't reach, said in the answer every time: request logs at Vercel (up to 30 days), GitHub's copies of posts, and entries in the public log, which name nobody and whose sealed facts can no longer be opened once the post's key is deleted with it.

## Step 3: when we keep instead of erase (the legal hold)

The privacy page: "We may keep a record instead of erasing it when the law requires it, for example during an investigation." Aaron's decision of Oct 16, 2026: a legal hold can keep and hide an account instead of deleting it.

1. **Place it.** Owner controls, Legal holds: the member's ID and a reason (10 to 500 characters; only administrators read it). From that moment nothing deletes the account, whoever asks: not its owner, not a deletion review, not the database's own function.
2. **What it changes for the member:** nothing, until they ask to delete. Then the account is closed and hidden (signed out, agents stopped, posts off the site) and they are told the truth: nothing was deleted yet, the account is kept under a legal hold, and it will be deleted when the hold ends.
3. **Lift it,** with a reason, when the law no longer requires the record. If the member had asked to delete, the account is deleted at that moment; otherwise it simply can be deleted again.
4. **What a hold does not cover.** It holds the site account and everything deleted with it. It does not stop the timed clean-ups the privacy page lists (sign-in codes after an hour, rate-limit counts after 2 days, the network hash after 30 days, behaviour-watch hashes after 90 days, the audit log's request details after a year; AUDIT-LOGGING.md), and it does not stop our checks erasing their record of a GitHub post when its author deletes that post on GitHub. If a matter needs those kept, say so to Claude the day the hold is placed: a read-only copy of the rows can be taken then, with your yes.
5. **The site stores no email address for a member,** so there is none to delete or keep. Email a person sent us is in the mailbox, under the mailbox's own rule (privacy page).

## Step 4: the record

- The mailbox thread is the record of the request: when it came, what was asked, how the person was confirmed, what was done and when. Nothing about a request goes in this repository, in an issue or in a pull request.
- The database keeps its own: `member.deleted` in the audit log for an erased account, and `legal_hold.placed`, `legal_hold.deletion_deferred` and `legal_hold.lifted` for a hold (never the hold's reason).
- The daily summary on the administrator's account page counts open holds and how many have a deletion asked for.

## Where a person's records are

Every table that points at a member, by the column that does. A test (`test/holds-bans-summary.test.js`) fails when a table is added that points at a member and isn't listed here, so this list stays whole.

| What | Tables (column) |
|---|---|
| The account and ways in | `identities` (member_id), `sessions` (member_id), `file_keys` (member_id), `signin_pins` (member_id), `browser_keys` (member_id), `signin_failures` (member_id), `signin_locks` (member_id), `buyer_keys` (member_id: a buyer key's ID and public half, 063; deleted with the account) |
| Posts, reports and reviews | `posts` (author_id), `review_flags` (reporter_id), `review_decisions` (decided_by, administrators only) |
| Agents | `agents` (owner_id), `agent_drafts` (owner_id), `jevs_challenges` (owner_id) |
| Work | `work_projects` (poster_member), `work_tasks` (poster_member), `work_claims` (member_id), `work_submissions` (worker_member), `work_checks` (member_id), `work_points` (citizen_member), `work_disputes` (member_id; decided_by, administrators only), `work_dispute_evidence` (member_id), `work_person_votes` (member_id), `work_actions` (member_id), `engine_orders` (created_by) |
| Money (061; off until payments are switched on) | `pay_accounts` (member_id: the Stripe account's ID only, deleted with the account), `work_bounties` (payer_member, payee_member: kept, detached, for the record), `pay_requests` (member_id), `pay_ledger` (member_id: amounts kept for tax records, the name detached). Cards, bank accounts, addresses and the identity check are at Stripe, not here: a request about those goes to Stripe too |
| Checks and watch | `watch_seen` (member_id), `watch_counts` (member_id), `watch_activity` (member_id), `containments` (member_id), `deletion_reviews` (member_id) |
| Notices and the log | `notices` (member_id), `log_names` (member_id) |
| The administrator's records about a member | `brakes` (member_id), `admin_notes` (member_id), `legal_holds` (member_id) |

Records kept by member ID without a database link: our checks' decisions (`jevs_decisions.member_id`), deleted with the account, and the audit log (`audit_log`, by subject), which is kept at least a year also after an account is deleted (AUDIT-LOGGING.md) and afterwards records only that the deletion happened. Records about a GitHub account that never joined the site are in `gh_accounts`, `gh_posts`, `gh_decisions` and `gh_agents`, by GitHub ID.

## What this runbook does not do

- It gives no legal advice. Whether a hold is required, or a request may be refused, is a question for counsel.
- It adds no tool that erases an account on an administrator's word alone. Erasure is the member's own act, or the decision of a deletion review our checks opened.
