# What runs here, and when

Every workflow sits directly in `.github/workflows`: GitHub reads them only from that folder, without subfolders. This page groups them instead. **Don't rename these files without changing what checks them:** four Supabase functions accept a GitHub identity token only from one exact file on main: the JEVs gate from `jevs.yml`, the migration runner from `database.yml`, the GitHub bridge (dog-github) from `github-facts.yml`, and the preview branch's dog-copy from `preview-copy.yml`. A renamed file would stop posts reaching the database, migrations being applied, or GitHub's facts being recorded.

## On pull requests and pushes to main (the checks)

| File | What it does |
|---|---|
| `checks.yml` | The required `checks` job: the full test suite on Postgres 17, Semgrep, gitleaks, ESLint and the pull-request guards (`scripts/pr-guards.js`); the tests include the checks that every generated page matches its source |
| `codeql.yml` | GitHub's CodeQL code scan (advisory) |
| `gate-guard.yml` | On pull requests only: runs main's copy of the pull-request guards, so a pull request can't weaken its own checks |

## When something on main changes (deploy-time automation)

| File | Trigger | What it does |
|---|---|---|
| `database.yml` | push to main, daily, by hand | Applies new migrations through the migration runner, and checks daily that the live database matches main |
| `jevs.yml` | GitHub discussions and comments; push (the bans file) | Sends GitHub posts and the ban list through the JEVs gate |
| `brake.yml` | push, by hand | When `moderation/brake` says on, locks every open discussion; off unlocks them |
| `preview-copy.yml` | push, by hand | Rebuilds the Supabase preview branch's database from main, with made-up data |

## On a schedule

| File | When | What it does |
|---|---|---|
| `uptime.yml` | every 15 minutes, and after each deployment | Checks the live site answers |
| `log-witness.yml` | every 15 minutes | Copies the public log's signed checkpoint to an independent witness |
| `github-facts.yml` | hourly, when a pull request closes, and on task issues | Sends GitHub's own facts (pull requests, task issues) to the database for the work module |
| `sorting.yml` | daily, and on new issues | The daily sorting run and queue for proposals (plain rules, no AI) |
| `watch.yml` | daily | Checks each live Edge Function matches main, and audits dependencies for known vulnerabilities; it alerts, never changes anything |

## When an issue is filed or edited

| File | What it does |
|---|---|
| `proposal-edits.yml` | Flags a proposal edited after it was approved |
| `red-team.yml` | Runs Aaron's own attack plan, from an issue he labels `red-team`, against a throwaway copy of the site, and comments the report |

## By hand only

| File | What it does |
|---|---|
| `setup.yml` | Production setup (run once; recorded in OPERATIONS.md) |
| `restore-test.yml` | The backup restore test |

## Other files

- `ISSUE_TEMPLATE/`: the proposal form.
- `codeql/`: CodeQL's settings.
- `rulesets/`: the branch rulesets as JSON, with a README saying which are applied.
