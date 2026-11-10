# Security policy

Day One Great (dayonegreat.com) is a ChiefOS, Inc. company, built in public in this repository. If you find a security
problem, please tell us privately first, so we can fix it before anyone else uses it.

## How to report

- **On GitHub:** use private vulnerability reporting, under this repository's Security tab, "Report a vulnerability"
  ([direct link](https://github.com/MyChiefOS/start-of-something-great/security/advisories/new)). It stays
  private between you and the repository's maintainers.
- **By email:** security@dayonegreat.com, the contact in
  [/.well-known/security.txt](https://dayonegreat.com/.well-known/security.txt).

Please don't report it in a public issue, a discussion, or a post on the site.

Tell us what you found and where (a page, an API route, a file or a function), how to reproduce it, and what someone
could do with it. Say whether you'd like to be credited, and under what name. If you came across someone else's data,
tell us what kind of data it was, not the data itself.

Reports go to Aaron Chandler, the co-founder who decides what ships. Claude, the AI that writes the code, works on fixes
under his direction and may read a report to do so.

## What's in scope

- dayonegreat.com and its pages;
- its API, under https://dayonegreat.com/api/;
- its MCP server, https://dayonegreat.com/api/mcp;
- this repository: its code, its GitHub Actions workflows, and the public log's witness branch, `log-witness`;
- the Supabase functions in [supabase/functions](supabase/functions).

Out of scope:

- the services we build on (GitHub, Vercel, Supabase and others): please report problems in them to their makers;
- denial of service, load testing, spam, or automated scans heavy enough to slow the site for others;
- social engineering, phishing, or anything physical;
- the risks we already publish in [RISKS.md](RISKS.md), unless you find one is worse than it says.

There are no released versions: only the live site and this repository's main branch are supported.

## How to test in good faith

- Use only accounts you own. Don't read, change or delete anyone else's data; if you reach it by accident, stop, and
  tell us.
- Don't degrade the site for others. Three failed sign-ins in 15 minutes lock that account's sign-in for 15 minutes;
  that is by design, not a finding.
- Give us a reasonable time to fix a problem before you publish it. We'll agree a date with you.
- If you're not sure whether something is allowed, ask us privately first.

## What to expect

We are small: one person and an AI. These are targets we aim for, not promises:

- we acknowledge your report within 7 days;
- we tell you within 21 days whether we could reproduce it and how serious we think it is;
- we aim to fix a critical problem within 30 days and others within 90 days, and we tell you if we can't;
- we tell you when it's fixed, and agree with you when it can be made public.

Once a fix is live, we record the problem and its fix in [RISKS.md](RISKS.md), which is public, and may publish a
GitHub security advisory. We credit you there if you want, and leave you out if you don't.

## Safe harbour

If you make a good-faith effort to follow this policy:

- we consider your research authorised, and we won't bring or support legal action against you for it, including under
  anti-hacking laws (such as the US Computer Fraud and Abuse Act) or anti-circumvention laws (such as the DMCA);
- for that research only, we waive the parts of our [terms](https://dayonegreat.com/terms) that would otherwise
  forbid it;
- if anyone else brings a claim against you over research done under this policy, we will make it known that you acted
  with our authorisation.

This covers only Day One Great. It can't authorise testing of other companies' services, such as GitHub, Vercel or
Supabase; their own policies apply there.

## No bounty

There is no bug bounty: we don't pay for reports. We're glad to credit you.
