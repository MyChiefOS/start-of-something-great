# Email setup (PR 13): what Aaron does in AWS and Vercel

Notices are in-app only (your decision, Oct 16, 2026): every notice lands in the member's inbox on the site (/account), and no member's email address is stored. This page switches on the one email the site sends: **email sign-in links**, through Amazon SES. The address someone types to sign in is used to send the link and isn't kept. Claude never sees, handles or types any of these values. You create the accounts, accept the terms and paste the secrets into Vercel yourself.

Until you finish, the site uses the "log" transport, which sends nothing, so email sign-in stays off and GitHub and X sign-in work as usual.

Time needed: about an hour of your time, plus AWS's review of production access (often about a day).

## 1. The AWS account and region

1. Create or choose the AWS account for ChiefOS, Inc. (your decision; Claude doesn't create accounts).
2. Pick one SES region and use it everywhere below, for example `us-west-2` (Oregon, nearest the Bay Area) or `us-east-1`. Avoid Milan and Zurich: they have no SMTP endpoints.

## 2. Verify the domain in SES (DKIM, SPF through a MAIL FROM domain, DMARC)

In the SES console, under **Configuration, Identities**, choose **Create identity**, then **Domain**, and enter `dayonegreat.com`:

- **DKIM:** choose Easy DKIM, RSA 2048-bit. SES shows three CNAME records.
- **Custom MAIL FROM domain:** choose "Use a custom MAIL FROM domain" and enter `bounce.dayonegreat.com`. Use a subdomain that receives no other mail, so your hello@ forwarding is untouched. Set "Behavior on MX failure" to "Reject message".

Gmail and Yahoo require SPF, DKIM and DMARC for any sender; one-click unsubscribe applies to marketing and bulk mail, and sign-in links are neither.

Then add these records in **Vercel, Domains, dayonegreat.com, DNS Records**. The domains were bought through Vercel, so their DNS is there:

| Type | Name | Value | Notes |
|---|---|---|---|
| CNAME | `<token1>._domainkey` | `<token1>.dkim.amazonses.com` | copy all three exactly from SES |
| CNAME | `<token2>._domainkey` | `<token2>.dkim.amazonses.com` | |
| CNAME | `<token3>._domainkey` | `<token3>.dkim.amazonses.com` | |
| MX | `bounce` | `feedback-smtp.<region>.amazonses.com`, priority 10 | only one MX on this subdomain |
| TXT | `bounce` | `v=spf1 include:amazonses.com ~all` | SPF for the MAIL FROM domain |
| TXT | `_dmarc` | `v=DMARC1; p=none; adkim=r; aspf=r; rua=mailto:hello@dayonegreat.com` | start at `p=none`; if a `_dmarc` record already exists, keep one record only |

Check before you add: if `dayonegreat.com` already has a DMARC record (for Google Workspace, for example), keep a single record and tell Claude what it says. After two clean weeks of DMARC reports, move to `p=quarantine`, then `p=reject`.

SES shows the identity as **Verified** once the records are seen, usually within minutes and up to 72 hours.

## 3. Bounces and complaints (a configuration set and an SNS topic)

1. **SNS:** create a Standard topic named `dayonegreat-email-events`, in the same region as SES. Copy its ARN (`arn:aws:sns:<region>:<account>:dayonegreat-email-events`).
2. **Switch the topic to SHA-256 signatures before subscribing.** SNS topics sign with `SignatureVersion` 1 (SHA1) by default, and the site accepts only version 2 (SHA-256). Set the topic's `SignatureVersion` attribute to `2` (in the console under the topic's settings, or with `aws sns set-topic-attributes --topic-arn <ARN> --attribute-name SignatureVersion --attribute-value 2`). Without it, the subscription in step 4 never confirms.
3. **Vercel first:** add `SNS_TOPIC_ARN` (step 6) and redeploy. The site accepts messages only from this topic, only from SNS in the topic's own region, and only with a good version 2 signature; it confirms the subscription by itself only after checking that signature.
4. **SNS subscription:** on the topic, choose **Create subscription**, protocol HTTPS, endpoint `https://dayonegreat.com/api/notify/sns`. It should show **Confirmed** within a minute.
5. **SES configuration set:** under **Configuration sets**, create `dayonegreat-signin`. Add an **event destination** of type Amazon SNS, choose the topic, and select the events **Bounce** and **Complaint**.
6. Optional, recommended: in **Suppression list** settings, turn on the account-level suppression list for bounces and complaints. It works alongside the site's own list, which keeps only a keyed fingerprint of each address (never the address) so no sign-in link is sent to it again.

## 4. Production access (out of the sandbox)

In SES, choose **Get set up, Request production access**. Suggested answers:

- Mail type: **Transactional**.
- Website: `https://dayonegreat.com`.
- Use case: "Sign-in links only (passwordless email sign-in) for Day One Great. Each email is sent only when someone asks for a link on our sign-in page, to the address they typed; we send no newsletters or notifications by email. Rate-limited per address and per network, with a site-wide ceiling. Bounces and complaints are suppressed automatically through SNS. Expected volume under 1,000 emails a day during the preview."

Until AWS approves, SES only sends to addresses you have verified yourself, which is enough to test with your own address.

## 5. A sending-only IAM user

In IAM, create a user `dayonegreat-ses-send` with no console access and this one inline policy. Use your region and account number; the From address must match `SES_FROM`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": "*",
      "Condition": { "StringEquals": { "ses:FromAddress": "signin@dayonegreat.com" } }
    }
  ]
}
```

Create one access key for it (type "Application running outside AWS"). It goes straight into Vercel in step 6; don't store it anywhere else. To narrow it further, set `Resource` to the identity's ARN and the configuration set's ARN.

## 6. Vercel environment variables (Production only)

Project Settings, Environment Variables, **Production** only, so preview deployments never send email. Mark the secret ones **Sensitive**:

| Name | Value | Secret? |
|---|---|---|
| `EMAIL_TRANSPORT` | `ses` | no |
| `SES_REGION` | your region, e.g. `us-west-2` | no |
| `SES_FROM` | `Day One Great <signin@dayonegreat.com>` | no |
| `SES_CONFIGURATION_SET` | `dayonegreat-signin` | no |
| `SNS_TOPIC_ARN` | the topic's ARN from step 3 | no |
| `SES_ACCESS_KEY_ID` | from step 5 | yes |
| `SES_SECRET_ACCESS_KEY` | from step 5 | yes |

No extra key is needed for bounces: their fingerprints use the sign-in fingerprint keys you already set (SIGNIN-SETUP.md), with a label of their own.

The names are `SES_*`, not `AWS_*`, because Vercel uses the `AWS_*` names for its own credentials.

**The timers are off in slice 1** (GATEWAY.md: they move to the gateway in a later slice, and their secret will be made inside the database and kept in Vault like the others, so nothing runs on your computer; the old instruction to make `CRON_SECRET` with `openssl` on your own computer is removed, Oct 23). When they return, `CRON_SECRET` turns on the every-minute timers at `/api/cron`: draft expiry, the 90-day check, the watch and pauses, and JEVs's 24-hour deletion-review timer and mark sweep. Vercel sends it to that route by itself, and only to the production deployment. Without it, the route answers "not switched on" and nothing runs, so set it with the preview. Every-minute cron jobs need Vercel Pro, which you chose (GAP-52). (A pause whose time is up also ends whenever its owner opens their agents, so a missed run never makes one longer.)

Redeploy after adding them.

## 7. Check it works (a few minutes)

1. Sign out, open **/join**, and ask for an email sign-in link to your own address (verified in SES if you're still in the sandbox).
2. Within a minute the link arrives. It opens a page with a **Continue** button; nothing happens until you press it, so mail scanners can't use it up.
3. In Gmail, open the message's menu, choose **Show original**, and check `SPF: PASS`, `DKIM: PASS` and `DMARC: PASS`.
4. Have one of your agents write a draft: it shows up in your inbox at **/account**, with its exact words and an **Approve** button, and no email.
5. In Vercel, under **Settings, Cron Jobs**, `/api/cron` runs every minute; its log shows counts only.

Record each step's result in OPERATIONS.md (or ask Claude to, with your concurrence).

## What the site does with email, in short

- Sends only sign-in links, each one when someone asks for it, to the address they typed. Notices stay in the inbox on the site; nothing else is emailed.
- Stores no member's address: the one typed at sign-in is used to send and kept only as the keyed fingerprint sign-in already uses.
- An address that bounced for good or complained is kept only as a keyed fingerprint, and no sign-in link is sent to it again. The page answers the same either way, so nobody learns which.
- Approving a draft, keeping an agent acting and confirming a held post all happen on the notice itself, signed in to your own account.
