const { getConversation, send, onlyGet } = require('./_lib');

module.exports = async (req, res) => {
  if (!onlyGet(req, res)) return;
  try {
    const limit = new URL(req.url, 'https://x').searchParams.get('limit');
    send(res, 200, await getConversation(limit), 300);
  } catch (e) {
    send(res, 502, { error: 'Could not reach GitHub right now. Try again shortly.' });
  }
};
