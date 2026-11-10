// A project's plan against verified work, drawn as Aaron's chart canvas of Nov 7 draws it ("Planned vs actual chart":
// the Build board, the project page and the same at phone width; design/canvas-2026-11-07/), on the handoff's "Scope
// and verified work": the thin line is scope, the dashed line is the plan (the size due by each day), the amber line is
// work with an anchored receipt, a dotted amber line runs from today at the last seven days' pace to the forecast
// finish, the time after the planned finish is shaded, and under the chart each milestone has a row: an outline mark
// at its planned date, a filled amber mark when it was done, a dashed mark at its forecast, and a line where its date
// moved. Then the status pills, the figures, the "Planned and actual dates" table and the plan's changes. Used by
// /build (the featured project) and /projects/<id>. Everything comes from /api/work/plan or the summary's plan; every
// word is set with textContent, and the drawing is SVG built element by element, so nothing anyone wrote runs.
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var WD = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var DAY = /^(20[0-9]{2})-([0-9]{2})-([0-9]{2})$/;
  var MS_DAY = 86400000;
  function t(s) { var m = DAY.exec(typeof s === 'string' ? s : ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) : NaN; }
  function iso(v) { var d = new Date(v); return d.getUTCFullYear() + '-' + ('0' + (d.getUTCMonth() + 1)).slice(-2) + '-' + ('0' + d.getUTCDate()).slice(-2); }
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
  function h(parent, tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; if (parent) parent.appendChild(e); return e; }
  function clear(box) { while (box.firstChild) box.removeChild(box.firstChild); }
  function path(pts) { return pts.length ? 'M' + pts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join('L') : ''; }
  // A step line: flat to each day, then up (the value holds for the whole day).
  function steps(days, key, x, y) {
    var out = [];
    days.forEach(function (d, i) {
      if (d[key] === null || d[key] === undefined) return;
      var px = x(t(d.day)), py = y(n(d[key]));
      if (out.length) out.push([px, out[out.length - 1][1]]);
      out.push([px, py]);
      if (i === days.length - 1 || days[i + 1][key] === null || days[i + 1][key] === undefined) out.push([x(t(d.day) + MS_DAY), py]);
    });
    return out;
  }
  function milestones(plan) { return (plan && Array.isArray(plan.milestones) ? plan.milestones : []).filter(function (m) { return m && !isNaN(t(m.first_target)); }); }
  // Done: its finish date is known, or every one of its tasks is done (a plan served before 054 has no finish date).
  function done(m) { return (m.done_on && !isNaN(t(m.done_on))) || (n(m.tasks) > 0 && n(m.tasks_done) === n(m.tasks)); }
  function dated(m) { return m.done_on && !isNaN(t(m.done_on)); }
  // A milestone's forecast at the last seven days' pace: what's left in it and every milestone before it, at that pace.
  // Null when it's done, when nothing was verified in the last seven days, or when it has no tasks yet.
  function forecasts(plan) {
    var f = (plan && plan.figures) || {}, pace = n(f.pace), today = t(plan && plan.today), left = 0, out = {};
    milestones(plan).forEach(function (m) {
      left += Math.max(0, n(m.size) - n(m.done_size));
      out[m.id] = done(m) || !n(m.tasks) || pace <= 0 || isNaN(today) ? null : iso(today + Math.ceil(left / pace) * MS_DAY);
    });
    return out;
  }

  function chart(box, plan) {
    clear(box);
    var days = (plan && Array.isArray(plan.days) ? plan.days : []).filter(function (d) { return d && !isNaN(t(d.day)); });
    var f = (plan && plan.figures) || {};
    if (days.length < 2) return false;
    var ms = milestones(plan), fc = forecasts(plan);
    var W = Math.max(300, Math.round(box.clientWidth || 520)), phone = W < 560;
    var L = phone ? 30 : 40, R = phone ? 10 : 14, T = 24, B = 26, CH = phone ? 200 : 260, ROW = phone ? 16 : 18;
    var H = CH + (ms.length ? 12 + ms.length * ROW : 0);
    var first = t(days[0].day), last = t(days[days.length - 1].day) + MS_DAY, today = t(plan.today);
    var top = Math.max(1, n(f.scope));
    top = Math.ceil((top * 1.1) / 4) * 4;
    function x(v) { return L + ((v - first) / (last - first)) * (W - L - R); }
    function y(v) { return CH - B - (v / top) * (CH - T - B); }
    var svg = el(box, 'svg', { viewBox: '0 0 ' + W + ' ' + H, width: '100%', role: 'img', 'class': 'plan-svg',
      'aria-label': 'Planned against verified work: ' + n(f.planned) + ' planned by today, ' + n(f.verified) + ' of ' + n(f.scope) + ' verified'
        + (f.forecast ? ', forecast to finish ' + long(f.forecast) : n(f.left) === 0 && n(f.scope) > 0 ? ', all of it verified' : '')
        + (f.gate ? ', against a planned finish of ' + long(f.gate) : '') + '.' });
    // After the planned finish (the release gate's first target, else the last milestone's): shaded, as the canvas.
    if (f.gate && !isNaN(t(f.gate))) {
      var gx = x(t(f.gate) + MS_DAY);
      if (gx < W - R) {
        el(svg, 'rect', { x: gx, y: T, width: W - R - gx, height: y(0) - T, 'class': 'shade' });
        if (W - R - gx > 110) el(svg, 'text', { x: gx + 8, y: T + 12, 'class': 'after' }, 'After the planned finish');
      }
    }
    var g = el(svg, 'g', { 'class': 'grid' });
    for (var i = 1; i <= 4; i++) el(g, 'line', { x1: L, x2: W - R, y1: y((top * i) / 4), y2: y((top * i) / 4) });
    el(svg, 'line', { x1: L, x2: W - R, y1: y(0), y2: y(0), 'class': 'axis' });
    var lab = el(svg, 'g', { 'class': 'lab' });
    [0, 2, 4].forEach(function (i) { el(lab, 'text', { x: L - 6, y: y((top * i) / 4) + 4, 'text-anchor': 'end' }, String((top * i) / 4)); });
    // Week labels: W1 is the plan's first week; at most seven (four on a phone), the one under "now" left out.
    var weeks = Math.ceil((last - first) / (7 * MS_DAY)), every = Math.max(1, Math.ceil(weeks / (phone ? 4 : 7)));
    for (var w = 0; w < weeks; w += every) {
      var mid = first + (w + 0.5) * 7 * MS_DAY;
      if (mid > last || Math.abs(x(mid) - x(today)) < 26) continue;
      el(lab, 'text', { x: x(mid), y: CH - 8, 'text-anchor': 'middle' }, 'W' + (w + 1));
    }
    // Each milestone's first target: a dashed rule, labelled with its code.
    var by = {};
    ms.forEach(function (m) { (by[m.first_target] = by[m.first_target] || []).push(String(m.code || '')); });
    Object.keys(by).forEach(function (d) {
      var mx = x(t(d) + MS_DAY / 2);
      if (mx < L || mx > W - R) return;
      el(svg, 'line', { x1: mx, x2: mx, y1: T, y2: y(0), 'class': 'mark' });
      el(lab, 'text', { x: mx, y: T - 6, 'text-anchor': 'middle' }, by[d].join(' '));
    });
    var nx = null;
    if (!isNaN(today)) {
      nx = x(today + MS_DAY / 2);
      el(svg, 'line', { x1: nx, x2: nx, y1: T, y2: H - 2, 'class': 'now' });
      el(svg, 'text', { x: nx, y: 12, 'text-anchor': 'middle', 'class': 'nowl' }, 'now');
    }
    el(svg, 'path', { d: path(steps(days, 'scope', x, y)), 'class': 'scope' });
    el(svg, 'path', { d: path(steps(days, 'planned', x, y)), 'class': 'planned' });
    var v = steps(days, 'verified', x, y);
    el(svg, 'path', { d: path(v), 'class': 'verified' });
    if (nx !== null && n(f.planned) > 0) {
      el(svg, 'circle', { cx: nx, cy: y(n(f.planned)), r: 3.5, 'class': 'pdot' });
      // The higher of the two figures is labelled above its line and the lower below, so the labels never meet.
      if (!phone) el(svg, 'text', { x: nx - 8, y: y(n(f.planned)) + (n(f.planned) > n(f.verified) ? -8 : 16), 'text-anchor': 'end', 'class': 'val' }, 'Planned ' + n(f.planned));
    }
    if (v.length) {
      var end = v[v.length - 1];
      if (f.forecast && !isNaN(t(f.forecast))) {
        var fx = Math.min(x(t(f.forecast) + MS_DAY / 2), W - R);
        el(svg, 'line', { x1: end[0], y1: end[1], x2: fx, y2: y(n(f.scope)), 'class': 'forecast' });
        el(svg, 'circle', { cx: fx, cy: y(n(f.scope)), r: 4.5, 'class': 'fdot' });
        el(svg, 'text', { x: fx, y: y(n(f.scope)) + 18, 'text-anchor': fx > W - R - 50 ? 'end' : 'middle', 'class': 'fl' }, (phone ? '' : 'Forecast ') + short(f.forecast));
      }
      el(svg, 'circle', { cx: end[0], cy: end[1], r: 5, 'class': 'dot' });
      var above = n(f.verified) >= n(f.planned), vr = end[0] + 10 > W - R - 70;
      el(svg, 'text', { x: vr ? end[0] - 10 : end[0] + 10, y: end[1] + (above ? -10 : 18), 'text-anchor': vr ? 'end' : 'start', 'class': 'val strong' }, (phone ? '' : 'Verified ') + n(f.verified));
    }
    // The milestone rows: planned (outline), done (filled), forecast (dashed), and the line between them.
    ms.forEach(function (m, k) {
      var ry = CH + 12 + k * ROW + ROW / 2;
      el(lab, 'text', { x: 2, y: ry + 4 }, String(m.code || ''));
      el(svg, 'line', { x1: L, x2: W - R, y1: ry, y2: ry, 'class': 'row' });
      var px = x(t(m.first_target) + MS_DAY / 2);
      var actual = dated(m) ? m.done_on : done(m) ? null : fc[m.id];
      var ax = actual ? Math.min(x(t(actual) + MS_DAY / 2), W - R) : null;
      if (ax !== null && Math.abs(ax - px) > 10) el(svg, 'line', { x1: Math.min(px, ax) + 5, x2: Math.max(px, ax) - 5, y1: ry, y2: ry, 'class': done(m) ? 'span' : 'span fc' });
      var dia = function (cx, cls) { el(svg, 'path', { d: 'M' + cx + ',' + (ry - 5) + 'L' + (cx + 5) + ',' + ry + 'L' + cx + ',' + (ry + 5) + 'L' + (cx - 5) + ',' + ry + 'Z', 'class': cls }); };
      if (ax !== null && Math.abs(ax - px) <= 10) { dia(px, done(m) ? 'dia done' : 'dia fc'); return; }
      dia(px, 'dia plan');
      if (ax !== null) dia(ax, done(m) ? 'dia done' : 'dia fc');
    });
    return true;
  }

  // The milestone pills under the chart (done, its share, or the release gate), as the handoff's.
  function pills(box, plan) {
    clear(box);
    milestones(plan).forEach(function (m) {
      var s = document.createElement('span');
      var share = m.share === null || m.share === undefined ? null : n(m.share);
      var due = short(m.target) + (m.moved ? ' (first ' + short(m.first_target) + ')' : '');
      if (done(m)) { s.className = 'pill m'; s.textContent = m.code + ' done'; }
      else if (m.gate) { s.className = 'pill'; s.textContent = m.code + ' release gate · ' + due; }
      else { s.className = 'pill a'; s.textContent = m.code + ' · ' + (share === null ? 'no tasks yet' : Math.floor(share * 100) + '%'); }
      s.title = m.title + ': ' + n(m.done_size) + ' of ' + n(m.size) + ' verified; target ' + due;
      box.appendChild(s);
    });
  }

  // The project's status, as the canvas's pills: ahead, on or behind plan, and the milestone it's on.
  function status(box, plan) {
    clear(box);
    var f = (plan && plan.figures) || {}, ms = milestones(plan);
    if (!ms.length || n(f.scope) === 0) return;
    var idx = f.index === null || f.index === undefined ? null : n(f.index);
    if (n(f.left) === 0) h(box, 'span', 'pill m', 'All verified');
    else if (idx !== null) h(box, 'span', idx < 1 ? 'pill a' : 'pill m', idx < 0.995 ? 'Behind plan' : idx > 1.005 ? 'Ahead of plan' : 'On plan');
    var at = 0;
    for (var i = 0; i < ms.length; i += 1) if (!done(ms[i])) { at = i + 1; break; }
    h(box, 'span', 'pill m', at ? ms[at - 1].code + ' of ' + ms.length : 'All ' + ms.length + ' milestones done');
  }

  // The schedule figures, into the elements named in ids (each optional), and one plain sentence.
  function figures(ids, plan) {
    var f = (plan && plan.figures) || {}, ms = milestones(plan);
    var set = function (k, v) { var e = ids[k] && document.getElementById(ids[k]); if (e) e.textContent = v; };
    var signed = function (v) { return (v > 0 ? '+' : v < 0 ? '−' : '') + Math.abs(v); };
    set('planned', String(n(f.planned)));
    set('verified', String(n(f.verified)));
    set('scope', String(n(f.scope)));
    set('share', n(f.scope) > 0 ? Math.floor((n(f.verified) / n(f.scope)) * 100) + '%' : '–');
    set('done', ms.filter(done).length + ' of ' + ms.length);
    set('variance', signed(n(f.variance)));
    set('index', f.index === null || f.index === undefined ? '–' : n(f.index).toFixed(2));
    set('forecast', f.forecast ? short(f.forecast) : n(f.left) === 0 && n(f.scope) > 0 ? 'Done' : '–');
    set('forecast-note', f.gate ? 'Forecast finish (plan ' + short(f.gate) + ')' : 'Forecast finish');
    var gate = f.gate ? long(f.gate) + (f.gate_target && f.gate_target !== f.gate ? ' (moved to ' + long(f.gate_target) + ')' : '') : null;
    var s = n(f.scope) === 0 ? 'Nothing is in this plan yet: its milestones fill as tasks are posted.'
      : n(f.left) === 0 ? 'Everything posted so far is verified: ' + n(f.tasks) + ' tasks' + (gate ? ', with the gate on ' + gate : '') + '. Work not yet posted as a task isn’t in the plan.'
      : !f.forecast ? n(f.left) + ' left, and nothing verified in the last seven days, so there is no forecast yet' + (gate ? '; the gate is ' + gate : '') + '.'
      : n(f.left) + ' left. At the last seven days’ pace it lands ' + long(f.forecast) + (gate ? ', ' + (n(f.slip_days) > 0 ? n(f.slip_days) + ' days after' : n(f.slip_days) < 0 ? -n(f.slip_days) + ' days before' : 'on') + ' the gate, ' + gate : '') + '.';
    if (n(f.unplanned) > 0) s += ' ' + n(f.unplanned) + ' in scope came after the last milestone, so no target covers it yet.';
    set('text', s);
    return f;
  }

  // "Planned and actual dates": a table on a wide screen, the same rows stacked on a phone (the canvas's two layouts).
  function table(tbody, list, plan) {
    clear(tbody); clear(list);
    var fc = forecasts(plan);
    milestones(plan).forEach(function (m) {
      var late = dated(m) ? Math.round((t(m.done_on) - t(m.target)) / MS_DAY) : null;
      var actual = dated(m) ? short(m.done_on) : done(m) ? 'Done' : fc[m.id] ? short(fc[m.id]) + ', forecast' : '–';
      var planned = short(m.first_target) + (m.moved ? ' (moved to ' + short(m.target) + ')' : '');
      var points = n(m.done_size) + ' of ' + n(m.size) + (n(m.size) && !done(m) ? ' · ' + Math.floor((n(m.done_size) / n(m.size)) * 100) + '%' : '');
      var st = done(m) ? (late === null ? ['Done', 'pill m'] : late <= 0 ? ['Done on time', 'pill m'] : ['Done, ' + late + (late === 1 ? ' day' : ' days') + ' late', 'pill m'])
        : !n(m.tasks) ? ['No tasks yet', 'pill'] : n(m.done_size) > 0 ? ['In progress', 'pill a'] : ['Not started', 'pill'];
      var name = String(m.code || '') + ' ' + String(m.title || '');
      var tr = h(tbody, 'tr');
      h(h(tr, 'td'), 'b', null, name);
      h(tr, 'td', null, planned); h(tr, 'td', null, actual); h(tr, 'td', null, points);
      h(h(tr, 'td'), 'span', st[1], st[0]);
      var li = h(list, 'li', 'ms');
      h(li, 'b', null, name); h(li, 'span', st[1], st[0]);
      h(li, 'span', 'fine', 'Planned ' + planned + ' · ' + (dated(m) ? 'done ' : '') + actual + ' · ' + points + ' points');
    });
  }

  // The plan's changes: milestones whose date moved (each keeps its first date), and scope added after the plan began.
  function changes(box, plan) {
    clear(box);
    var ms = milestones(plan), days = (plan && plan.days) || [], f = (plan && plan.figures) || {}, any = false;
    ms.forEach(function (m) {
      if (!m.moved) return;
      any = true;
      h(box, 'p', 'fine', m.code + ' ' + String(m.title || '') + ': moved from ' + long(m.first_target) + ' to ' + long(m.target) + '. The plan keeps the first date, so the move shows as time behind or ahead.');
    });
    if (ms.length && days.length) {
      var start = t(ms[0].first_target), at = null;
      days.forEach(function (d) { if (t(d.day) <= start) at = n(d.scope); });
      if (at !== null && n(f.scope) > at) {
        any = true;
        h(box, 'p', 'fine', 'Scope ' + at + ' to ' + n(f.scope) + ' since ' + long(ms[0].first_target) + ': tasks posted after the first milestone join the next one due, so the plan fills as they arrive.');
      }
    }
    if (!any) h(box, 'p', 'fine', 'No changes: every milestone keeps its first date.');
  }

  window.DOGPlan = { chart: chart, pills: pills, status: status, figures: figures, table: table, changes: changes, short: short, long: long };
})();
