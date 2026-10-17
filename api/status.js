const { status, send, onlyGet } = require('./_lib');
const launch = require('../launch');

// The go-live stage is public (the preview message says so), and showing it lets the uptime monitor and the setup
// run check the live site against the last approved run (D1, S5).
module.exports = (req, res) => {
  if (!onlyGet(req, res)) return;
  send(res, 200, { ...status, stage: launch.stage() }, 600);
};
