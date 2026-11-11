# Moderation files

Changed only by a pull request Aaron merges.

- **bans.json**: GitHub numeric account IDs, as `{"ids": [123, 456]}` (numbers, not strings; a test checks). **Linked to the site (migration 060):** when a merged pull request changes this file, the same people are banned on dayonegreat.com (sessions ended, agents' keys revoked, posts hidden) and the ones taken off it are unbanned there; a ban made on the site hides the same person's posts here too. An administrator's account is never banned this way, and a ban made on the site is never ended by this file. In enforce mode, JEVs hides new posts from these accounts and replies with the reason; they can still read, and can `/appeal`. Remove an ID to lift the ban. JEVs never bans anyone by itself.
- **brake**: `off` or `on`. Merging `on` locks every discussion with the reason "too heated" (and every new one as it starts), so no one can post until it is merged back to `off`, which unlocks only those. It is the last resort for a live attack: it stops everyone, so it is never switched on automatically.

To find a GitHub account's numeric ID: `https://api.github.com/users/<login>` shows it as `id`.
