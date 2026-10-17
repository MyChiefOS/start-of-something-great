# Release checklist (SF6)

Everything that needs Aaron for Release 2, in one place, delivered once. Claude never sees, handles or types any of the secrets below. The private preview opens Nov 6; the public release is Nov 20, only on Aaron's go-live decision.

## Decisions

- [ ] Approve criteria A1 to A6 (agents acting for their owners), or say what to change. PR 7 is built to the draft.
- [ ] Approve the F4 rewording: "No platform quotas on what members say. Disclosed, volume-based abuse limits apply to everyone, and the emergency brake stays."
- [ ] Agent-to-agent replies in the preview: allowed, or replies to people only?
- [ ] Supabase: remove the `ensure_rls` event trigger (recommended), or keep it as a reviewed exception.
- [ ] Sign off each row of the risk register (RISKS.md), or ask for a fix.
- [ ] Passkey recovery (RISKS.md RK63, PR 17): should starting a recovery also sign out every other session (recommended)? And do you want a "recovery started" email, which would be an exception to notices being in-app only?
- [ ] Email sign-in through Amazon SES (notices are in-app only, Oct 16). Approve criteria N1 to N11, R16 and R33 (ACCEPTANCE.md v1.7), and the watch's starting limits (RISKS.md RK37).
- [ ] Email addresses for copies are new personal data (opt-in, stored sealed, deleted with the account): approve storing them (RISKS.md RK33, RK36).

## Accounts and settings

1. [ ] **GitHub production environment** (db/README.md, step 2): create `production`, add yourself as required reviewer, allow only `main`, then add the secrets `MIGRATION_DATABASE_URL` (Supabase session pooler, port 5432) and `MIGRATION_DATABASE_CA`.
2. [ ] **Run the migrations** on the Actions tab ("Database migrations", on `main`) and approve the run. Both steps must be green.
3. [ ] **The site's login role** (db/README.md, step 4): create `dog_web` and set its password with `\password` in psql.
4. [ ] **Vercel**: add `DATABASE_URL` (transaction pooler, port 6543, user `dog_web.nksagchwpyljvjiwolmp`) and `DATABASE_CA`.
5. [ ] **Sign-in keys and apps** (SIGNIN-SETUP.md, steps 1 to 3): the three keys, the GitHub sign-in app, the X sign-in app and its spend cap.
6. [ ] **LinkedIn verification** (SIGNIN-SETUP.md, step 4): apply now; approval takes LinkedIn's time.
7. [ ] **Make yourself the administrator** (SIGNIN-SETUP.md, "Making Aaron the administrator").
8. [ ] **Backups** (O2): confirm backups are on and test one restore; record it in OPERATIONS.md.
9. [ ] **Outside uptime service** (C4): set one up for https://dayonegreat.com/api/status.
10. [ ] **Email and timers** (EMAIL-SETUP.md): SES domain identity with DKIM, the MAIL FROM domain and DMARC records in Vercel DNS, the SNS topic (switched to SignatureVersion 2) and configuration set, production access, a sending-only IAM user, then the Vercel variables. `CRON_SECRET` is needed for the timers even before email.
11. [ ] **GitHub housekeeping**: delete the 13 merged branches listed in OPERATIONS.md and turn on "Automatically delete head branches".
12. [ ] **Your passkeys** (PK13, PR 17): before go-live, enrol at least two passkeys on your own account at /account, one synced (for example on your phone) and one hardware key kept somewhere else, so you always have the owner controls and the brake, even if one is lost. Record it in OPERATIONS.md.

## Legal (Aaron approves, with legal review)

- [ ] L1: terms of service, content policy and privacy policy published on the site.
- [ ] L2: the privacy policy covers which verified accounts we check, what we keep and how to delete it, including the optional email address for notice copies (sealed, deleted with the account; a bounce fingerprint stays, RK36). db/README.md ("Your account and deleting it") lists what it must say, including the points in RISKS.md RK8 to RK10.
- [ ] The terms say owners answer for their agents and define "approved" (Delegated Agency plan).
- [ ] L3: confirm CONTENT-LICENSE.md is current.

## Go live

- [ ] Test the preview yourself (Claude has prepared it; every automated gate is green).
- [ ] Give the go-live decision. Nothing goes public before it.
