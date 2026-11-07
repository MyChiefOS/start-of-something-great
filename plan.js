// A project's plan, drawn as the design draws it (050; the handoff's Build page, "Scope and verified work"): the dashed
// line is planned scope (the size due by each day), the amber line is work with an anchored receipt, a dotted line is
// the last seven days' pace to the forecast, a dashed rule marks each milestone's target and an amber one today. Then
// the milestone pills (done, its share, or the release gate) and the schedule figures. Used by /build (the featured
// project) and /projects/<id>. Everything comes from /api/work/plan or the summary's plan; every word is set with
// textContent, and the drawing is SVG built element by element, so nothing anyone wrote runs.
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var WD = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var DAY = /^(20[0-9]{2})-([0-9]{2})-([0-9]{2})$/;
  function t(s) { var m = DAY.exec(typeof s === 'string' ? s : ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) : NaN; }
  function short(s) { var d = new Date(t(s)); return isNaN(d) ? '' : MON[d.getUTCMonth()] + ' ' + d.getUTCDate(); }
  function long(s) { var d = new Date(t(s)); return isNaN(d) ? '' : WD[d.getUTCDay()] + ', ' + short(s); }
  function n(x) { var v = Number(x); return Number.isFinite(v) ? v : 0; }
  function el(parent, name, attrs, text) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, String(attrs[k]));
    if (text !== undefined) e.textContent = text;
    parent.appendChild(e);
    return e;
  }
  function path(pts) { return pts.length ? 'M' + pts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join('L') : ''; }
  // A step line: flat to each day, then up (the value holds for the whole day).
  function steps(days, key, x, y) {
    var out = [];
    days.forEach(function (d, i) {
      if (d[key] === null || d[key] === undefined) return;
      var px = x(t(d.day)), py = y(n(d[key]));
      if (out.length) out.push([px, out[out.length - 1][1]]);
      out.push([px, py]);
      if (i === days.length - 1 || days[i + 1][key] === null || days[i + 1][key] === undefined) out.push([x(t(d.day) + 86400000), py]);
    });
    return out;
  }

  function chart(box, plan) {
    while (box.firstChild) box.removeChild(box.firstChild);
    var days = (plan && Array.isArray(plan.days) ? plan.days : []).filter(function (d) { return d && !isNaN(t(d.day)); });
    var f = (plan && plan.figures) || {};
    if (days.length < 2) return false;
    var W = Math.max(300, Math.round(box.clientWidth || 520)), H = 260, L = 34, R = 14, T = 22, B = 30;
    var first = t(days[0].day), last = t(days[days.length - 1].day) + 86400000, today = t(plan.today);
    var top = Math.max(1, n(f.scope));
    top = Math.ceil((top * 1.1) / 4) * 4;
    function x(v) { return L + ((v - first) / (last - first)) * (W - L - R); }
    function y(v) { return H - B - (v / top) * (H - T - B); }
    var svg = el(box, 'svg', { viewBox: '0 0 ' + W + ' ' + H, width: '100%', role: 'img', 'class': 'plan-svg',
      'aria-label': 'Planned scope and verified work by day: ' + n(f.verified) + ' of ' + n(f.scope) + ' verified, ' + n(f.planned) + ' planned by today.' });
    var g = el(svg, 'g', { 'class': 'grid' });
    for (var i = 1; i <= 4; i++) el(g, 'line', { x1: L, x2: W - R, y1: y((top * i) / 4), y2: y((top * i) / 4) });
    el(svg, 'line', { x1: L, x2: W - R, y1: y(0), y2: y(0), 'class': 'axis' });
    var lab = el(svg, 'g', { 'class': 'lab' });
    [0, 2, 4].forEach(function (i) { el(lab, 'text', { x: L - 6, y: y((top * i) / 4) + 4, 'text-anchor': 'end' }, String((top * i) / 4)); });
    // Week labels: W1 is the plan's first week; at most seven labels, the one under "now" left out.
    var weeks = Math.ceil((last - first) / 604800000), every = Math.max(1, Math.ceil(weeks / 7));
    for (var w = 0; w < weeks; w += every) {
      var mid = first + (w + 0.5) * 604800000;
      if (mid > last || Math.abs(x(mid) - x(today)) < 26) continue;
      el(lab, 'text', { x: x(mid), y: H - 8, 'text-anchor': 'middle' }, 'W' + (w + 1));
    }
    // Milestones: a dashed rule at each first target (the plan; a moved one shows its new date on its pill), labelled.
    var by = {};
    (plan.milestones || []).forEach(function (m) { if (!isNaN(t(m.first_target))) (by[m.first_target] = by[m.first_target] || []).push(String(m.code || '')); });
    Object.keys(by).forEach(function (d) {
      var mx = x(t(d) + 43200000);
      if (mx < L || mx > W - R) return;
      el(svg, 'line', { x1: mx, x2: mx, y1: T - 4, y2: y(0), 'class': 'mark' });
      el(lab, 'text', { x: mx, y: T - 8, 'text-anchor': 'middle' }, by[d].join(' '));
    });
    if (!isNaN(today)) {
      var nx = x(today + 43200000);
      el(svg, 'line', { x1: nx, x2: nx, y1: T - 4, y2: y(0), 'class': 'now' });
      el(svg, 'text', { x: nx, y: H - 8, 'text-anchor': 'middle', 'class': 'nowl' }, 'now');
    }
    el(svg, 'path', { d: path(steps(days, 'scope', x, y)), 'class': 'scope' });
    el(svg, 'path', { d: path(steps(days, 'planned', x, y)), 'class': 'planned' });
    var v = steps(days, 'verified', x, y);
    el(svg, 'path', { d: path(v), 'class': 'verified' });
    if (v.length) {
      var end = v[v.length - 1];
      if (f.forecast && !isNaN(t(f.forecast))) {
        var fx = Math.min(x(t(f.forecast) + 43200000), W - R);
        el(svg, 'line', { x1: end[0], y1: end[1], x2: fx, y2: y(n(f.scope)), 'class': 'forecast' });
        el(svg, 'circle', { cx: fx, cy: y(n(f.scope)), r: 4, 'class': 'fdot' });
      }
      el(svg, 'circle', { cx: end[0], cy: end[1], r: 5, 'class': 'dot' });
    }
    return true;
  }

  function pills(box, plan) {
    while (box.firstChild) box.removeChild(box.firstChild);
    (plan && plan.milestones || []).forEach(function (m) {
      var s = document.createElement('span');
      var share = m.share === null || m.share === undefined ? null : n(m.share);
      var due = short(m.target) + (m.moved ? ' (first ' + short(m.first_target) + ')' : '');
      if (m.gate) { s.className = 'pill'; s.textContent = m.code + ' release gate · ' + due; }
      else if (share !== null && share >= 1 && t(m.target) <= t(plan.today)) { s.className = 'pill m'; s.textContent = m.code + ' done'; }
      else { s.className = 'pill a'; s.textContent = m.code + ' · ' + (share === null ? 'no tasks yet' : Math.floor(share * 100) + '%'); }
      s.title = m.title + ': ' + n(m.done_size) + ' of ' + n(m.size) + ' verified; target ' + due;
      box.appendChild(s);
    });
  }

  // The schedule figures, into the elements named in ids (each optional), and one plain sentence.
  function figures(ids, plan) {
    var f = (plan && plan.figures) || {};
    var set = function (k, v) { var e = ids[k] && document.getElementById(ids[k]); if (e) e.textContent = v; };
    var signed = function (v) { return (v > 0 ? '+' : v < 0 ? '−' : '') + Math.abs(v); };
    set('planned', String(n(f.planned)));
    set('verified', String(n(f.verified)));
    set('variance', signed(n(f.variance)));
    set('index', f.index === null || f.index === undefined ? '–' : n(f.index).toFixed(2));
    set('forecast', f.forecast ? short(f.forecast) : n(f.left) === 0 && n(f.scope) > 0 ? 'Done' : '–');
    var gate = f.gate ? long(f.gate) + (f.gate_target && f.gate_target !== f.gate ? ' (moved to ' + long(f.gate_target) + ')' : '') : null;
    var s = n(f.scope) === 0 ? 'Nothing is in this plan yet: its milestones fill as tasks are posted.'
      : n(f.left) === 0 ? 'Everything posted so far is verified: ' + n(f.tasks) + ' tasks' + (gate ? ', with the gate on ' + gate : '') + '. Work not yet posted as a task isn\u2019t in the plan.'
      : !f.forecast ? n(f.left) + ' left, and nothing verified in the last seven days, so there is no forecast yet' + (gate ? '; the gate is ' + gate : '') + '.'
      : n(f.left) + ' left. At the last seven days’ pace it lands ' + long(f.forecast) + (gate ? ', ' + (n(f.slip_days) > 0 ? n(f.slip_days) + ' days after' : n(f.slip_days) < 0 ? -n(f.slip_days) + ' days before' : 'on') + ' the gate, ' + gate : '') + '.';
    if (n(f.unplanned) > 0) s += ' ' + n(f.unplanned) + ' in scope came after the last milestone, so no target covers it yet.';
    set('text', s);
    return f;
  }

  window.DOGPlan = { chart: chart, pills: pills, figures: figures, short: short, long: long };
})();
