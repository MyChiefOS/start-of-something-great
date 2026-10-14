const { getChanges, send, onlyGet, githubLimit } = require('./_lib');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  try {
    const limit = new URL(req.url, 'https://x').searchParams.get('limit');
    const data = await getChanges(limit);
    if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
    send(res, 200, data, 300);
  } catch (e) {
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
