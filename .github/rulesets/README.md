# Rulesets prepared for Aaron's approval

GitHub doesn't apply these files by itself, and Claude's sessions can't change repository settings (they answer 403).
Each takes effect only when Aaron applies it.

## log-witness.json (the independent review of Nov 5, M4)

On the branch `log-witness`, no force-push (`non_fast_forward`) and no deletion, with no one allowed to bypass. Applied
by Aaron on Nov 10, 2026 (ruleset 26948314, active).

What it does and doesn't do:

- It keeps the witness's record from being deleted or rewritten. The repository's owner can still edit or switch off
  the ruleset, so it can't lock Aaron out, and it doesn't stop him either.
- It doesn't stop new commits. The witness workflow pushes without force, so it keeps working. Anyone with write access
  to the repository, Claude's sessions included, can also add an ordinary commit, and a commit can change what
  `state.json` says, including dropping an alarm (RISKS.md RK149).
- The witness's own job no longer does that (RK149's fix): it starts a fresh branch only when GitHub says the branch
  doesn't exist, fails if the branch moved after its check, and `record()` in tools/verify/witness.mjs refuses a state
  that drops an alarm, lowers the last good checkpoint, changes the pinned key or lowers the run count. A commit by
  someone else stays in the branch's public history, since the ruleset keeps that history.

To apply it in the browser: download log-witness.json from this folder on GitHub to your computer, then in the
repository's Settings, Rules, Rulesets, New ruleset, Import a ruleset, choose the downloaded file. GitHub's import takes
a file from your own computer, not one from the repository. Check that Enforcement shows Active before saving (the
file asks for Active; a ruleset made by hand starts Disabled).

Optional, only if the GitHub CLI is set up on Aaron's computer, signed in as the repository's owner (the browser route
above needs nothing installed):

    gh api repos/MyChiefOS/start-of-something-great/rulesets --method POST --input .github/rulesets/log-witness.json
