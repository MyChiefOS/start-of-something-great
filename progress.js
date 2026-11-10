// The featured project's progress in one figure and one sentence, as the Build page's hero and the home page's card
// both show it (so they never differ; the design handoff's "Proposed next" card, decided for JEVs, Nov 10, Q3): the
// share of its scope verified, rounded down, and what that counts. All of it verified reads "all posted work verified",
// never "done": work not yet posted as a task isn't in the plan (RISKS.md RK132). Its own small file, so the home page
// doesn't load the whole chart (plan.js). From /api/work/plan's answer; the caller sets it with textContent.
(function () {
  'use strict';
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var WD = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var DAY = /^(20[0-9]{2})-([0-9]{2})-([0-9]{2})$/;
  function t(s) { var m = DAY.exec(typeof s === 'string' ? s : ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) : NaN; }
  function long(s) { var d = new Date(t(s)); return isNaN(d) ? '' : WD[d.getUTCDay()] + ', ' + MON[d.getUTCMonth()] + ' ' + d.getUTCDate(); }
  function n(x) { var v = Number(x); return Number.isFinite(v) ? v : 0; }
  function plural(k, one) { return k === 1 ? '1 ' + one : k + ' ' + one + 's'; }
  window.DOGProgress = function (plan) {
    var f = (plan && plan.figures) || {}, pr = (plan && plan.project) || {};
    var ms = (plan && Array.isArray(plan.milestones) ? plan.milestones : []).filter(function (m) { return m && !isNaN(t(m.first_target)); });
    var pct = n(f.scope) ? Math.floor((100 * n(f.verified)) / n(f.scope)) : 0;
    var gate = ms.filter(function (m) { return m.gate; })[0];
    var note = String(pr.title || '') + ' · ' + plural(ms.length, 'milestone') + ' · ' + plural(n(f.tasks), 'task')
      + ' · ' + (n(f.left) === 0 && n(f.scope) ? 'all posted work verified' : f.forecast ? 'expected ' + long(f.forecast) : 'no forecast yet')
      + (gate ? ', the gate ' + long(gate.target) : '');
    return { pct: pct, note: note, project: pr };
  };
})();
