const { getProposals, send, onlyGet, githubLimit } = require('./_lib');
const { shapeShipped } = require('./_proposals');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  try {
    const data = shapeShipped(await getProposals());
    if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
    send(res, 200, data, 120, 60);
  } catch (e) {
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
