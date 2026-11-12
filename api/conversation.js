const { getConversation, getTopics, send, onlyGet, githubLimit } = require('./_lib');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  await require('../db/sitekeys').ensure(req); // route B: the login and keys from the broker, only while open
  try {
    const q = new URL(req.url, 'https://x').searchParams;
    // ?topics=1: only the list of topics (USE-CASES.md row 20). Otherwise one thread: the welcome thread, or ?topic=<number>.
    if (q.get('topics') === '1') {
      const topics = await getTopics();
      if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
      return send(res, 200, { topics, note: 'Each topic is a GitHub discussion started by Day One Great\u2019s own account. Read one with /api/conversation?topic=<number>.' }, 60, 60);
    }
    const data = await getConversation(q.get('limit'), q.get('topic'));
    if (githubLimit()) res.setHeader('X-GitHub-Rate-Limit', githubLimit());
    // At most a minute fresh and a minute stale at the edge, so a post JEVs hides leaves agents' answers within about two
    // minutes; an answer whose hidden-post check failed is not cached at all (fix 2 review: the default stale time
    // would have kept a since-hidden post for up to a day).
    if (data.hidden_posts && data.hidden_posts.filter === 'unavailable') send(res, 200, data, 0);
    else send(res, 200, data, 60, 60);
  } catch (e) {
    // A topic that isn't a number (400) or isn't one of the topics (404): said plainly, and never cached as a thread.
    if (e && (e.status === 400 || e.status === 404)) return send(res, e.status, { error: e.publicMessage }, 0);
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
