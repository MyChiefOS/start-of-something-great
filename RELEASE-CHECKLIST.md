# Release checklist (SF6)

Everything that needs Aaron for Release 2, in one place. Claude never sees, handles or types any secret. Release 2 stays off until the go-live stage (launch.js) moves from `closed` (the default) to `public`, which is Aaron's go-live decision. There is no preview stage (Aaron, Oct 24: "NO preview systems"); `preview` counts as closed. Under route B (Oct 26) the remaining steps are Claude's PRs; Aaron approves them.

Decided on Oct 16 and recorded in CHARTER.md section 2, so no longer on this list: criteria A1 to A6, the F4 wording, agent-to-agent replies with a depth limit, removing Supabase's `ensure_rls` trigger (the setup run does it), notices in-app only, and the regional gate in code.

## Decisions

- [ ] Sign off each row of the risk register (RISKS.md), or ask for a fix, including RK62 (who may delete an account).
- [ ] Approve criteria N1 to N11, R16 and R33 (ACCEPTANCE.md), and the watch's starting limits (RISKS.md RK37).
- [ ] Linking a new sign-in method signs out the session that linked it (PR 15): keep it, or say so.

## Accounts and settings

All from GitHub, nothing on your computer: **SETUP.md** has every step and marks each value only you can supply.

1. [ ] **The `production` environment** with you as required reviewer, administrator bypass off, `main` only, and its three secrets (SETUP.md, steps 1 and 2).
2. [ ] **First setup run, still closed** (SETUP.md, step 3): migrations, the site's login role, `DATABASE_URL`, the sign-in keys and `CRON_SECRET`, the coverage check. You read the run's plan before approving it. The site doesn't change.
3. [x] **The GitHub sign-in app** (SIGNIN-SETUP.md): done Oct 16.
4. [ ] **The X sign-in app** and its spending limit (SIGNIN-SETUP.md).
5. [x] ~~Open the preview for yourself~~: removed Oct 26, 2026. There is no preview stage (Aaron, Oct 24). Making Aaron administrator is fix 9 (harness/PLAN.md), whose method is his open decision.
6. [ ] **Email sign-in links** (EMAIL-SETUP.md, Amazon SES): your AWS account with SES production access, and the SPF, DKIM and DMARC records.
7. [ ] **Backups** (O2): confirm backups are on in Supabase, and run the **Restore test** workflow (SETUP.md, step 7); record both in OPERATIONS.md.
8. [x] ~~Before go-live: enrol two passkeys~~: removed Oct 24, 2026: Aaron's instruction, passkeys dropped.
9. [ ] **GitHub housekeeping:** turn on "Automatically delete head branches" and delete the branches that are fully merged (OPERATIONS.md lists them). Never delete a branch whose work isn't in main.

## Legal (Aaron approves, with legal review)

- [ ] L1: terms of service, content policy and privacy policy published on the site.
- [ ] L2: the privacy policy covers which verified accounts we check, what we keep and how to delete it: JEVs's checks, the deletion review and legal hold, the traveller notice, in-app notices, and, once built, Stripe Identity's reference and result (never the images). db/README.md ("Your account and deleting it") lists what it must say, including RISKS.md RK8 to RK10.
- [ ] The terms say owners answer for their agents and define "approved" (Delegated Agency plan).
- [ ] L3: confirm CONTENT-LICENSE.md is current.

## Go live

- [x] ~~Test the preview yourself~~: removed Oct 26, 2026 (no preview stage). Every automated gate stays green; fix 10's live proof is Claude's (harness/PLAN.md).
- [ ] Give the go-live decision: run Production setup with the stage `public`. Nothing goes public before it.
