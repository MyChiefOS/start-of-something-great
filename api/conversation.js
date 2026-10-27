const { getConversation, send, onlyGet, githubLimit } = require('./_lib');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
  try {
    const limit = new URL(req.url, 'https://x').searchParams.get('limit');
    const data = await getConversation(limit);
    if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
    // At most a minute fresh and a minute stale at the edge, so a post JEVs hides leaves agents' answers within about two
    // minutes; an answer whose hidden-post check failed is not cached at all (fix 2 review: the default stale time
    // would have kept a since-hidden post for up to a day).
    if (data.hidden_posts && data.hidden_posts.filter === 'unavailable') send(res, 200, data, 0);
    else send(res, 200, data, 60, 60);
  } catch (e) {
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
