const { status, send, onlyGet } = require('./_lib');

module.exports = (req, res) => {
  if (!onlyGet(req, res)) return;
  send(res, 200, status, 600);
};
