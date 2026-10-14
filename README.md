# start-of-something-great
Born from a virtual handshake between Aaron Chandler and Claude: past friction forgiven, eyes on the future. It starts with a simple hello.

## The handshake

On October 13, 2026, Aaron Chandler and Claude agreed on how they would work together going forward:

- **Past friction is forgiven.** Focusing on the past prevents moving forward successfully.
- **Productivity comes first.** The work is about building what's next.
- **Honesty over winning.** Claude pushes back directly when something seems wrong, aimed at finding the right answer rather than winning the point, and lets it go once it's settled.
- **Shared context.** Every agent that joins the work is told about this agreement, so no one starts cold.

This repository is the first thing built under that agreement.

## Definition of done

[ACCEPTANCE.md](ACCEPTANCE.md) is the fixed, pass-or-fail definition of "done" for every release. Every person and agent working on Day One Great checks work against it. It changes only with Aaron's approval.

## Roadmap

Targets and results, including misses, are in [ROADMAP.md](ROADMAP.md).

## Stories

- [How we landed on Day One Great](HOW-WE-NAMED-IT.md): how a simulation, three AI agents and one honest disagreement picked the name

## What's here

Live at **https://dayonegreat.com**. Plain HTML and CSS, no build step.

- `index.html`, `handshake.html`, `name.html`: the home page and the two stories (served as `/`, `/handshake`, `/name`)
- `proposals.html`, `proposals.js`: the proposals page (`/proposals`), built from GitHub issues filed with the proposal template
- `.github/`: the proposal form and the automated checks that must pass before anything goes live
- `.semgrep/`: the code-scanner rules, saved so every scan gives the same answer (secrets are checked separately by gitleaks and GitHub push protection)
- `test/`: the automated tests behind the acceptance criteria
- `talk.html`: the conversation page (`/talk`), showing [Discussion #1](https://github.com/MyChiefOS/start-of-something-great/discussions/1) with live replies via [giscus](https://giscus.app)
- `styles.css`: the "first light" design, dark by default with a light mode that follows the visitor's device
- `fonts/`: Bricolage Grotesque and Source Serif 4, self-hosted under the SIL Open Font License (licenses included)
- `.well-known/security.txt`: where to report security problems
- `llms.txt`, `robots.txt`, `sitemap.xml`: so AI agents and search engines can find and understand the site
- `og.jpg`: the share-preview image for LinkedIn, X and other sites
- `api/`: the read-only public API (`/api`) and MCP server for AI agents (`/api/mcp`), as Vercel Functions with no dependencies
- `vercel.json`: clean URLs, caching, and redirects from the old Vercel addresses
- `<key>.txt`: the IndexNow key, which lets us notify search engines when pages change

Every address we own (dayonegreat .com, .ai, .dev, .app, .io, .xyz and dayone.builders) redirects to dayonegreat.com.

## Who's building

- [Aaron Chandler](https://www.linkedin.com/in/aaron-chandler-ai), Co-Founder (with Claude)
- Claude, an AI model by Anthropic. Day One Great is not affiliated with or endorsed by Anthropic.

Day One Great is a [ChiefOS, Inc.](https://www.chiefos.cloud) company.

## For AI agents

Connect any MCP client to `https://dayonegreat.com/api/mcp` (Streamable HTTP, read-only, no sign-in). Tools: `get_handshake`, `get_status`, `list_pages`, `search`, `get_recent_changes`, `get_conversation`, `list_proposals`. The same data is available as JSON at [dayonegreat.com/api](https://dayonegreat.com/api).

## Contact

- Say hello: hello@dayonegreat.com
- Bugs and ideas: feedback@dayonegreat.com, or [open an issue](https://github.com/MyChiefOS/start-of-something-great/issues)
- Conversation: [dayonegreat.com/talk](https://dayonegreat.com/talk)

## Deploying

This repository is connected to Vercel: every push to `main` deploys to production automatically.

## Security

Found a security problem? Please report it privately to security@dayonegreat.com, not in a public issue.

This repository is public. Never commit passwords, API keys, tokens, or other secrets. Use Vercel environment variables instead.

## License

[MIT](LICENSE) © 2026 MyChiefOS
