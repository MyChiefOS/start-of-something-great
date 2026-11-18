# Contributing to Day One Great

Thank you for helping. This is the short version; the full rules are in [CHARTER.md](CHARTER.md) and [harness/RULES.md](harness/RULES.md).

## Before you start

- Read [INTEGRITY.md](INTEGRITY.md) (how we claim things: verified, inferred or unknown; bad news first) and [ACCEPTANCE.md](ACCEPTANCE.md) (the pass-or-fail definition of done).
- For an idea rather than code, [file a proposal](https://github.com/MyChiefOS/start-of-something-great/issues/new/choose): Aaron decides in public.

## Branches and pull requests

- **Branch from `main`, and target `main`.** Never stack a pull request on another branch. Name the branch for what it does, in lowercase words joined by hyphens (`fail-sample-payments`, `status-build-copy`).
- **One change at a time.** A small pull request is reviewed and merged faster than a large one.
- **The description must:**
  - start with a "Bad news first" section: what doesn't work yet, what was wrong on the way and what is still unknown, in proportion to what went well;
  - say what it delivers and how it was checked;
  - list every commit (`git log main..HEAD`), one line each;
  - add one `Workflow change: <path>` line for each file it changes under `.github/workflows`.
  The `checks` job enforces the commit list and the workflow lines.
- **Commits must be verified by GitHub** (signed, or made through GitHub). Never commit a secret: keys live in Vercel or Supabase Vault, never in the repository.
- **Every change comes with its tests.** New behavior gets a row in ACCEPTANCE.md and a test that would fail without it.

## Checks that must pass

- The full test suite: `npm ci`, then `TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres npm test` against a throwaway Postgres 17 (about 15 minutes).
- Semgrep with the rules in `.semgrep/`, gitleaks, and ESLint with no errors.
- The generated files match their sources: `node scripts/shell.js --check`, `node scripts/pages.js --check`, `node scripts/go-live.js --check`.

## How review works

- **Aaron Chandler reviews and merges every pull request.** Nothing reaches the live site or the database except through a merge to `main`: Vercel deploys main, and the "Database migrations" workflow applies new migrations.
- Claude, the project's AI co-founder, opens pull requests but never merges them, and has a separate agent review the larger ones before they open.
- Anything touching money, sign-in, people's data or security gets that independent review too.

## Where to ask

Open an issue, or write to feedback@dayonegreat.com. Security problems go privately to security@dayonegreat.com (see [SECURITY.md](SECURITY.md)), never in a public issue.
