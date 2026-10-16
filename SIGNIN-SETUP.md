# Sign-in setup kit

Everything Aaron needs to switch sign-in on, prepared so his part is short. Claude can't create accounts, handle secrets, spend money or accept terms of service for anyone, so each step below is Aaron's. Everything around those steps is ready.

Order: the database first (db/README.md, steps 1 to 5), then the steps below. Sign-in stays off until all of its settings are present.

## 1. The three keys (about 2 minutes)

On your own computer, in this repository's folder:

```sh
npx vercel@62.0.0 login
npx vercel@62.0.0 link
bash scripts/setup-signin-keys.sh
```

The script makes `SESSION_SECRET`, `IP_HASH_KEY` and `FINGERPRINT_KEY_1` and puts them straight into Vercel as secrets (Production only). It never prints or saves them, and nobody can read them back afterwards. If a key already exists, it leaves it alone.

## 2. GitHub sign-in app (about 3 minutes)

Open this link while signed in to GitHub as MyChiefOS (a personal account, not an organization; the organization link redirects to GitHub's Enterprise trial page, which we don't need, so don't start a trial there):

https://github.com/settings/applications/new

Or: profile picture → Settings → Developer settings → OAuth Apps → New OAuth App. If the repository later moves into a GitHub organization, the app can be transferred with it.

GitHub may not fill the form in from a link, so here are the values to paste:

| Field | Value |
|---|---|
| Application name | Day One Great |
| Homepage URL | `https://dayonegreat.com` |
| Application description | Sign in to Day One Great. We only learn which GitHub account you are; we keep a one-way fingerprint of it, never your name, username or email. |
| Authorization callback URL | `https://dayonegreat.com/auth/github/callback` |
| Enable Device Flow | Leave unchecked |

Then:
1. Click "Generate a new client secret".
2. In Vercel's project settings, under Environment Variables, add `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` for **Production only**.

The secret is shown once. Paste it straight into Vercel and don't save it anywhere else.

## 3. X sign-in app (about 10 minutes, plus a small prepaid credit)

Go to https://console.x.com (X's developer console; it moved from developer.x.com), sign in, and click New App. Then, in the app's user authentication settings, use these:

| Setting | Value |
|---|---|
| App name | Day One Great |
| App permissions | Read |
| Type of app | Web App, Automated App or Bot (a confidential client) |
| Callback URI / Redirect URL | `https://dayonegreat.com/auth/x/callback` |
| Website URL | `https://dayonegreat.com` |
| Terms of service | `https://dayonegreat.com/handshake` until the terms page exists (PR 7) |
| Privacy policy | Needs a privacy policy page, coming in PR 7. X may require it before approving. |

Description, if X asks for one:

> Day One Great is a community where people and the AI agents that act for them propose and build changes in the open. We use Sign in with X only to confirm which X account someone holds and whether X has verified it as a business or government account. We read the signed-in account once per sign-in, keep only a one-way fingerprint and the verification level, and never post, read timelines or store names, usernames or messages.

Then:
1. Under "Keys and tokens", copy the OAuth 2.0 Client ID and Client Secret into Vercel as `X_CLIENT_ID` and `X_CLIENT_SECRET`, for Production only.
2. In the console's billing area, buy a small prepaid credit, set a spending limit per billing cycle (requests stop when it's reached), and leave auto-recharge off. Each X sign-in costs about $0.01, so $10 covers about 1,000 sign-ins. If the credit runs out, X sign-in fails safely, and GitHub and email keep working.

## What Claude does around these steps

- Checks each setting by its name once you say it's added, without reading its value: Vercel shows that a variable exists, not what it says.
- Runs the database migrations once you approve the run in GitHub.
- Tests sign-in end to end on the live site, and records each action in OPERATIONS.md.
