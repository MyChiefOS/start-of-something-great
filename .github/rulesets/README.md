# Rulesets prepared for Aaron's approval

GitHub doesn't apply these files by itself, and Claude's sessions can't change repository settings (they answer 403).
Each takes effect only when Aaron applies it.

## log-witness.json (the independent review of Nov 5, M4)

Keeps the public log's witness record from being rewritten: on the branch `log-witness`, no force-push (`non_fast_forward`)
and no deletion, with no one allowed to bypass. The witness workflow only ever adds commits, so it keeps working.

To apply: Settings, then Rules, then Rulesets, then New ruleset, then Import a ruleset, and choose this file. Or, signed
in as the repository's owner:

    gh api repos/MyChiefOS/start-of-something-great/rulesets --method POST --input .github/rulesets/log-witness.json
