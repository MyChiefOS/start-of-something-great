# Moderation files

Changed only by a pull request Aaron merges.

- **bans.json**: GitHub numeric account IDs, as `{"ids": [123, 456]}`. In enforce mode, JEVs hides new posts from these accounts and replies with the reason; they can still read, and can `/appeal`. Remove an ID to lift the ban. JEVs never bans anyone by itself.
- **brake**: `off` or `on`. Merging `on` locks every open discussion, so no one can post until it is merged back to `off`. It is the last resort for a live attack: it stops everyone, so it is never switched on automatically.

To find a GitHub account's numeric ID: `https://api.github.com/users/<login>` shows it as `id`.
