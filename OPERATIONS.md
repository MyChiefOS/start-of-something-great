# Operations log

Every action Claude takes on Day One Great's accounts or settings for Aaron, in the open. It covers changes outside the code itself: settings, workflow runs, branches, and anything on GitHub or Vercel that isn't a pull request. Code changes are already recorded by their pull requests and commits.

How each entry happens:
1. Claude proposes the action and how to undo it.
2. Aaron concurs in the conversation, and the entry records when.
3. Claude acts, then records the result.

Some things Claude never does, even when asked:
- create accounts
- type or handle passwords, keys, client secrets or tokens
- spend money
- accept terms of service

Those stay with Aaron. The log starts on October 15, 2026; earlier actions are in the pull requests and conversation history.

Times are UTC.

| When | Action | Where | Aaron's concurrence | How to undo | Result |
|---|---|---|---|---|---|
| 2026-10-15 16:23 | Started the daily sorting run by hand, because GitHub's scheduler skipped the 14:00 and 15:00 runs (D3 missed its 16:00 deadline; recorded as late) | GitHub Actions: "Daily sorting run" | 16:2x, "yes" to starting it by hand | Nothing to undo; the next run replaces the queue | Ran in 10 seconds; issue #11 shows the Oct 15 queue, and closed #3 and #12 are gone |
| 2026-10-15 17:06 | Pushed branch `signin-pr2` (PR 2's work) to GitHub as a backup before opening its pull request | GitHub branch | Part of the build plan Aaron approved ("continue building the system") | Delete the branch | Pushed; no pull request or deploy until it opens |
| pending | Delete 12 branches whose pull requests are closed (10 merged, 2 closed with nothing unmerged); keep `main`, `main-snapshot-2026-10-14` and `signin-pr2` | GitHub branches | Asked 17:2x; waiting | "Restore branch" on each closed pull request; no commits are lost | Not done yet |
| pending | Turn on "Automatically delete head branches" | GitHub repository settings | Asked 17:2x; waiting | Turn it off in the same place | Not done yet |
