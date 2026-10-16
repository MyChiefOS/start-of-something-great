# Email setup (PR 13): what Aaron does in AWS and Vercel

Notices already work without any of this: every notice lands in the member's inbox on the site (/account) first. This page switches on the **email copies** and **email sign-in links**, sent through Amazon SES. Claude never sees, handles or types any of these values. You create the accounts, accept the terms and paste the secrets into Vercel yourself.

Until you finish, the site uses the "log" transport. It sends nothing, and members aren't offered email copies until `NOTIFY_KEY` is set. **Set `NOTIFY_KEY` last**, once SES can really send.

Time needed: about an hour of your time, plus AWS's review of production access (often about a day).

## 1. The AWS account and region

1. Create or choose the AWS account for ChiefOS, Inc. (your decision; Claude doesn't create accounts).
2. Pick one SES region and use it everywhere below, for example `us-west-2` (Oregon, nearest the Bay Area) or `us-east-1`. Avoid Milan and Zurich: they have no SMTP endpoints.

## 2. Verify the domain in SES (DKIM, SPF through a MAIL FROM domain, DMARC)

In the SES console, under **Configuration, Identities**, choose **Create identity**, then **Domain**, and enter `dayonegreat.com`:

- **DKIM:** choose Easy DKIM, RSA 2048-bit. SES shows three CNAME records.
- **Custom MAIL FROM domain:** choose "Use a custom MAIL FROM domain" and enter `bounce.dayonegreat.com`. Use a subdomain that receives no other mail, so your hello@ forwarding is untouched. Set "Behavior on MX failure" to "Reject message".

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

1. **SNS:** create a Standard topic named `dayonegreat-email-events`. Copy its ARN (`arn:aws:sns:<region>:<account>:dayonegreat-email-events`).
2. **Vercel first:** add `SNS_TOPIC_ARN` (step 6) and redeploy. The site accepts messages only from this topic, and it confirms the subscription by itself only after checking SNS's signature.
3. **SNS subscription:** on the topic, choose **Create subscription**, protocol HTTPS, endpoint `https://dayonegreat.com/api/notify/sns`. It should show **Confirmed** within a minute.
4. **SES configuration set:** under **Configuration sets**, create `dayonegreat-notices`. Add an **event destination** of type Amazon SNS, choose the topic, and select the events **Bounce** and **Complaint** (and Delivery if you want counts later).
5. Optional, recommended: in **Suppression list** settings, turn on the account-level suppression list for bounces and complaints. It works alongside the site's own list.

## 4. Production access (out of the sandbox)

In SES, choose **Get set up, Request production access**. Suggested answers:

- Mail type: **Transactional**.
- Website: `https://dayonegreat.com`.
- Use case: "Opt-in copies of in-app notices for members of Day One Great (drafts waiting for approval, safety notices) and sign-in links. Members add and confirm their own address (double opt-in). At most one email per member per hour, quiet hours, RFC 8058 one-click unsubscribe in every message, bounces and complaints suppressed automatically through SNS. Expected volume under 1,000 emails a day during the preview."

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
      "Condition": { "StringEquals": { "ses:FromAddress": "notices@dayonegreat.com" } }
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
| `SES_FROM` | `Day One Great <notices@dayonegreat.com>` | no |
| `SES_CONFIGURATION_SET` | `dayonegreat-notices` | no |
| `SNS_TOPIC_ARN` | the topic's ARN from step 3 | no |
| `SES_ACCESS_KEY_ID` | from step 5 | yes |
| `SES_SECRET_ACCESS_KEY` | from step 5 | yes |
| `CRON_SECRET` | a random string of 32 or more characters: run `openssl rand -base64 32` on your own computer and paste the output | yes |
| `NOTIFY_KEY` | **last**, the same way: `openssl rand -base64 32` | yes |

The names are `SES_*`, not `AWS_*`, because Vercel uses the `AWS_*` names for its own credentials.

`CRON_SECRET` turns on the every-minute timers (draft expiry, the 90-day check, the watch and pauses) and the email drain at `/api/cron`. Vercel sends it to that route by itself. Without it, the route answers "not switched on" and nothing runs, not even the in-app timers, so set it with the preview.

`NOTIFY_KEY` seals members' addresses, fingerprints them for bounces and signs unsubscribe links. **Never change or delete it once members have added addresses:** changing it makes their stored addresses unreadable (they would have to add them again), and old unsubscribe links stop working (RISKS.md, RK33).

Redeploy after adding them.

## 7. Check it works (a few minutes)

1. Sign in, open **/account**, and under **Email copies** add your own address (verified in SES if you're still in the sandbox).
2. Within a minute, a "Confirm email copies" email arrives. Open the link, check what it says, press **Confirm**.
3. Have one of your agents write a draft. Within a minute or two, an email with the agent's exact words and an approval link arrives. The link opens a page that shows the words; nothing happens until you press **Approve**.
4. In Gmail, open the message's menu, choose **Show original**, and check `SPF: PASS`, `DKIM: PASS` and `DMARC: PASS`, and that an **Unsubscribe** link appears next to the sender.
5. In Vercel, under **Settings, Cron Jobs**, `/api/cron` runs every minute; its log shows counts only.

Record each step's result in OPERATIONS.md (or ask Claude to, with your concurrence).

## What the site does with email, in short

- Sends only copies of notices that are already in the member's inbox, only to an address the member confirmed, at most one an hour, never in their quiet hours (default 22:00 to 07:00 their time).
- Every email has one-click unsubscribe (RFC 8058). Bounced and complained addresses are never emailed again.
- Approval and "keep acting" links do nothing by themselves: the member presses a button, signed in to their own account.
- Addresses are stored sealed, never logged, and deleted with the account.
