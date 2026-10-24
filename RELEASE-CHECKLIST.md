# Release checklist (SF6)

Everything that needs Aaron for Release 2, in one place. Claude never sees, handles or types any secret. Release 2 stays off until Aaron sets the go-live stage (launch.js): `closed` (the default), `preview` (only the people he allow-lists), then `public`, which is the go-live decision. The private preview target is Nov 6 and the public release Nov 20, only on Aaron's go-live decision.

Decided on Oct 16 and recorded in CHARTER.md section 2, so no longer on this list: criteria A1 to A6, the F4 wording, agent-to-agent replies with a depth limit, removing Supabase's `ensure_rls` trigger (removed Oct 23 with Aaron's approval; its leftover function `public.rls_auto_enable()` still waits for his agreement, OPERATIONS.md), notices in-app only, and the regional gate in code.

## Decisions

- [ ] Sign off each row of the risk register (RISKS.md), or ask for a fix, including RK62 (who may delete an account).
- [ ] Approve criteria N1 to N11, R16 and R33 (ACCEPTANCE.md), and the watch's starting limits (RISKS.md RK37).
- [ ] Linking a new sign-in method signs out the session that linked it (PR 15): keep it, or say so.
- [ ] A "recovery started" email for passkeys (PR 17), which would change "notices are in-app only": yes or no.

## Accounts and settings

All from GitHub, nothing on your computer. Since Oct 23 (Aaron: "remove the Old Path") launching needs no secret from you: the database is built, and its login and keys were made inside it and kept in Supabase Vault (GATEWAY.md). The old items "add the setup secrets", "first setup run" and "enrol two passkeys (PK13)" are removed.

1. [ ] **The `production` environment** with you as required reviewer, administrator bypass off, `main` only (SETUP.md, step 1). No secret is needed to launch; one is added only on the day you choose a run that needs it (SETUP.md, step 2).
2. [x] **The database** (migrations 001 to 017, row-level security forced on every table, the narrow login and keys in Vault): built Oct 23 with Aaron's approval (OPERATIONS.md).
3. [x] **The GitHub sign-in app** (SIGNIN-SETUP.md): done Oct 16.
4. [ ] **The X sign-in app** and its spending limit (SIGNIN-SETUP.md).
5. [ ] **Sign in and post** in the preview, which opens for your GitHub account only (GATEWAY.md, step 4), then **make yourself the administrator** (SETUP.md, step 3; Claude can do it with no secret once you agree).
6. [ ] **Email sign-in links** (EMAIL-SETUP.md, Amazon SES): your AWS account with SES production access, and the SPF, DKIM and DMARC records.
7. [ ] **Backups** (O2): confirm backups are on in Supabase, and run the **Restore test** workflow (SETUP.md, step 5); record both in OPERATIONS.md.
8. [ ] **GitHub housekeeping:** turn on "Automatically delete head branches" and delete the branches that are fully merged (OPERATIONS.md lists them). Never delete a branch whose work isn't in main.

## Legal (Aaron approves, with legal review)

- [ ] L1: terms of service, content policy and privacy policy published on the site.
- [ ] L2: the privacy policy covers which verified accounts we check, what we keep and how to delete it: JEVs's checks, the deletion review and legal hold, the traveller notice, in-app notices, and, once built, Stripe Identity's reference and result (never the images). db/README.md ("Your account and deleting it") lists what it must say, including RISKS.md RK8 to RK10.
- [ ] The terms say owners answer for their agents and define "approved" (Delegated Agency plan).
- [ ] L3: confirm CONTENT-LICENSE.md is current.

## Go live

- [ ] Test the preview yourself, with the stage at `preview` (every automated gate is green).
- [ ] Give the go-live decision: the gateway's stage and Production setup's stage (`stage,redeploy`, stage `public`) both move to `public` on your recorded words. Nothing goes public before it.
