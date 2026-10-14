const { getProposals, send, onlyGet, githubLimit } = require('./_lib');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  try {
    const data = await getProposals();
    if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
    // P2: at most 2 minutes cached plus 1 minute stale, well inside the 5-minute target.
    send(res, 200, data, 120, 60);
  } catch (e) {
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
