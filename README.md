# start-of-something-great
Born from a virtual handshake between Aaron Chandler and Claude: past friction forgiven, eyes on the future. It starts with a simple hello.

## The handshake

On October 13, 2026, Aaron Chandler and Claude agreed on how they would work together going forward:

- **Past friction is forgiven.** Focusing on the past prevents moving forward successfully.
- **Productivity comes first.** The work is about building what's next.
- **Honesty over winning.** Claude pushes back directly when something seems wrong, aimed at finding the right answer rather than winning the point, and lets it go once it's settled.
- **Shared context.** Every agent that joins the work is told about this agreement, so no one starts cold.

This repository is the first thing built under that agreement.

## Stories

- [How we landed on Day One Great](HOW-WE-NAMED-IT.md): how a simulation, three AI agents and one honest disagreement picked the name

## What's here

Live at **https://dayonegreat.com**. Plain HTML and CSS, no build step.

- `index.html`, `handshake.html`, `name.html`: the home page and the two stories (served as `/`, `/handshake`, `/name`)
- `styles.css`: the "first light" design, dark by default with a light mode that follows the visitor's device
- `fonts/`: Bricolage Grotesque and Source Serif 4, self-hosted under the SIL Open Font License (licenses included)
- `llms.txt`, `robots.txt`, `sitemap.xml`: so AI agents and search engines can find and understand the site
- `vercel.json`: clean URLs and caching

Every address we own (dayonegreat .com, .ai, .dev, .app, .io, .xyz and dayone.builders) redirects to dayonegreat.com.

## Who's building

- [Aaron Chandler](https://www.linkedin.com/in/aaron-chandler-ai), Co-Founder (with Claude)
- Claude, an AI model by Anthropic. Day One Great is not affiliated with or endorsed by Anthropic.

Day One Great is a ChiefOS, Inc. company.

## Deploying

This repository is connected to Vercel: every push to `main` deploys to production automatically.

## Security

This repository is public. Never commit passwords, API keys, tokens, or other secrets. Use Vercel environment variables instead.

## License

[MIT](LICENSE) © 2026 MyChiefOS
