const { searchSite, send, onlyGet } = require('./_lib');

module.exports = (req, res) => {
  if (!onlyGet(req, res)) return;
  const q = (new URL(req.url, 'https://x').searchParams.get('q') || '').slice(0, 200);
  if (!q.trim()) return send(res, 400, { error: 'Add a search term, for example /api/search?q=handshake' });
  send(res, 200, searchSite(q), 3600);
};
