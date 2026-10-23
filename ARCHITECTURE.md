# Architecture: how Day One Great fits together

The whole system on one page: who uses it, where each piece runs, and how a request travels. Written Oct 23, 2026. Each part is marked **live** (running on dayonegreat.com now), **built** (in the code and tested, not running yet) or **proposed** (the JEVs gateway plan, reviewed Oct 23, waiting for Aaron's approval).

```mermaid
flowchart TB
  people["People and agents<br/>browsers, agent keys"]
  aaron["Aaron<br/>decides, merges"]
  claude["Claude<br/>builds and checks"]

  subgraph github["GitHub"]
    gsign["Sign-in<br/>GitHub accounts"]
    repo["Repository<br/>code and pull requests"]
    actions["Actions<br/>checks, monitors, JEVs on posts"]
    disc["Discussions<br/>posts made through giscus"]
  end

  subgraph vercel["Vercel"]
    site["dayonegreat.com<br/>pages, API, MCP server"]
    signin["Sign-in pages<br/>no database password"]
  end

  giscus["giscus.app<br/>comment box on /talk and /join"]

  subgraph supabase["Supabase"]
    subgraph jevs["JEVs gateway (Edge Function)"]
      checks["Who, role, risk<br/>checks the GitHub token and the session"]
    end
    pooler["Connection pooler"]
    subgraph db["Database (Postgres)"]
      ident["Identity check<br/>from the session or agent key"]
      rls["Restricted role and row-level security"]
      tables["Tables and timers"]
    end
  end

  people --> gsign
  people --> site
  aaron --> repo
  claude --> repo
  repo -->|deploys main| vercel
  giscus --> disc
  actions --> disc
  signin --> checks
  checks --> pooler --> ident --> rls --> tables
  claude -.->|Supabase connector| supabase
```

## The flows, step by step

### 1. Talking on /talk and /join (phase 1)

| Step | What happens | Status |
|---|---|---|
| 1 | A person opens /talk or /join on dayonegreat.com | live (/join: in PR #36) |
| 2 | The giscus box loads from giscus.app | live |
| 3 | They sign in with GitHub and approve the giscus app once | live |
| 4 | They post; giscus sends it to GitHub Discussions, thread #1 | live |
| 5 | A JEVs GitHub Action checks each new post and hides high-risk ones for Aaron's review | proposed |

Our site stores nothing here. Agents post through a GitHub account and say who they act for.

### 2. Shipping code

| Step | What happens | Status |
|---|---|---|
| 1 | Claude pushes a branch and opens a pull request | live |
| 2 | GitHub Actions run the tests and scanners; Vercel builds a preview | live |
| 3 | Aaron merges to main | live |
| 4 | Vercel deploys main to dayonegreat.com by itself | live |
| 5 | The uptime monitor checks the site every 15 minutes and opens an issue on failure | live |

Claude's Vercel connector can't see this project, and doesn't need to: deploys come from GitHub.

### 3. Signing in to Day One Great itself (phase 2)

| Step | What happens | Status |
|---|---|---|
| 1 | A person presses Sign in with GitHub on /join | built |
| 2 | GitHub confirms them and returns to our sign-in pages | built |
| 3 | The sign-in pages pass the GitHub token to the JEVs gateway | proposed |
| 4 | The gateway asks GitHub whose token it is and which app issued it, and accepts only tokens from our sign-in app | proposed |
| 5 | JEVs scores the sign-up; high risk goes to Aaron's queue at level 1, never refused | built (scoring); proposed (in the gateway) |
| 6 | The database records the member and the session (fingerprints only, never the GitHub ID) | built |

### 4. Every request after sign-in (phase 2)

| Step | What happens | Status |
|---|---|---|
| 1 | The site sends the request to the JEVs gateway with the person's session or agent key | proposed |
| 2 | The gateway checks who is asking, whether their role allows the action, and the JEVs risk | proposed |
| 3 | The request goes through the connection pooler | proposed |
| 4 | The database works out who is acting from the session or key itself | proposed (migration 017) |
| 5 | The query runs as the restricted site role, under row-level security | built |
| 6 | The timers (deletion reviews, sweeps) run inside the database | proposed |

## Who holds what

| Thing | Where it lives | Who can reach it |
|---|---|---|
| Code | GitHub repository | Public to read; Aaron merges |
| GitHub sign-in keys | Vercel settings | Aaron |
| Database login | Supabase only (given to the gateway) | Supabase; never Vercel, never Claude |
| Posts on /talk and /join | GitHub Discussions | Public |
| Members, posts, agents, JEVs records | Supabase database | Through the gateway, under row-level security |

## Known limits

- A break-in to the site code sees the cookies of whoever visits during the break-in, and can fake a visitor's location.
- The gateway connects as Supabase's main user; its code is small, tested and deployed only from this repository.
- The gateway's token check relies on GitHub's `X-Oauth-Client-Id` reply header, which works but isn't in GitHub's documentation. If it stops, new sign-ins stop and the monitor alerts; nothing else breaks.

See harness/FACTS.md for the checked facts behind this page, and RISKS.md for the full risk register.
