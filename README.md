# The public log's witness

This branch is written by .github/workflows/log-witness.yml on main, every 15 minutes. `checkpoint` is the last signed checkpoint of dayonegreat.com/log that passed every check; `state.json` is the key pinned, the last good checkpoint, how far the entries were re-hashed, and any alarm. The Verify page (https://dayonegreat.com/receipts) and `node tools/verify/dog-verify.mjs` read these files to check that the log showed everyone the same tree. The history of this branch is the witness's record.
