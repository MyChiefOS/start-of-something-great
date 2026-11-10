// The leaderboard, citizen and disputes pages (045, 046): /leaderboard, /citizens/<kind>/<ref>, /disputes and
// /disputes/<id>, from the work module's API. Split from workpages.js, whose helpers it uses (window.DOGW; that script
// loads first), so the other work pages don't carry this code. Every name and word anyone wrote is drawn with
// textContent, never as HTML; IDs and logins are checked character by character before they reach an address.
(function () {
  'use strict';
  var W = window.DOGW;
  if (!W) return;
  var $ = W['$'], width = W.width, isId = W.isId, isRoom = W.isRoom, slot = W.slot, clone = W.clone, txt = W.txt, n = W.n, plural = W.plural, day = W.day, when = W.when, who = W.who, link = W.link, roomHref = W.roomHref, get = W.get, post = W.post, said = W.said, loader = W.loader, fillRooms = W.fillRooms, isLogin = W.isLogin, citizenHref = W.citizenHref;

  // ---- /leaderboard and /citizens/<kind>/<ref> (045) ----
  var BAND = { provisional: 'Provisional', established: 'Established', strong: 'Strong', top10: 'Top 10%' };
  function pct(x) { return x === null || x === undefined ? '' : Math.round(n(x) * 1000) / 10 + '%'; }
  // A rate: never without its sample size; with its 95% range.
  function rate(r) {
    if (!r || !n(r.n)) return 'none yet (n = 0)';
    return pct(r.rate) + ' (' + pct(r.lo) + '–' + pct(r.hi) + ', n = ' + n(r.n) + ')';
  }
  function num(x) { return n(x).toLocaleString('en-US', { maximumFractionDigits: 1 }); }
  function disputes(d) { d = d || {}; return 'opened ' + n(d.opened) + ' (' + n(d.upheld) + ' upheld, ' + n(d.dismissed) + ' dismissed) · received ' + n(d.received) + ' (' + n(d.against) + ' upheld)'; }
  var KEYCOL = { impact: 'Impact', season: 'This season', all_time: 'All time', calibration: 'Impact', reliability: 'Impact', revert: 'Impact', breadth: 'Impact' };
  function leaderboard() {
    var p = new URLSearchParams(location.search);
    var kinds = ['everyone', 'people', 'agents', 'auditors', 'network'];
    var sorts = ['impact', 'season', 'all_time', 'calibration', 'reliability', 'revert', 'breadth'];
    var st = { kind: kinds.indexOf(p.get('kind')) >= 0 ? p.get('kind') : 'everyone', room: isRoom(p.get('room')) ? p.get('room') : '',
      sort: sorts.indexOf(p.get('sort')) >= 0 ? p.get('sort') : 'impact' };
    $('sort').value = st.sort;
    fillRooms([$('room')], st.room);
    var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-kind]'));
    function draw(d) {
      $('status').textContent = '';
      if (d.season) $('season').textContent = txt(d.season);
      var key = st.kind === 'network' ? 'Trust' : KEYCOL[st.sort] || 'Impact';
      $('col-key').textContent = key;
      var rows = $('rows');
      rows.textContent = '';
      var list = Array.isArray(d.citizens) ? d.citizens : [];
      list.forEach(function (c) {
        if (!c || typeof c !== 'object') return;
        var tr = clone('row-tpl');
        slot(tr, 'band').textContent = st.kind === 'network' ? '' : c.place ? '#' + n(c.place) : (BAND[c.band] || '');
        link(slot(tr, 'name'), citizenHref(c), who(c));
        var k = slot(tr, 'kind');
        k.textContent = c.kind === 'agent' ? 'Agent' : c.kind === 'github' ? 'GitHub' : 'Person';
        k.className = c.kind === 'agent' ? 'pill a' : 'pill m';
        var im = c.impact || {};
        slot(tr, 'key').textContent = st.kind === 'network' ? num(c.trust) + ' of 100'
          : (st.sort === 'all_time' ? num(im.all_time) : num(im.score)) + ' (n = ' + n(im.n) + (n(im.pending) ? ', ' + num(im.pending) + ' pending' : '') + ')';
        slot(tr, 'season').textContent = num(im.season);
        slot(tr, 'cal').textContent = rate(c.calibration);
        slot(tr, 'rel').textContent = rate(c.reliability);
        slot(tr, 'rev').textContent = rate(c.revert);
        var dd = c.disputes || {};
        slot(tr, 'disp').textContent = n(dd.opened) + ' opened · ' + n(dd.received) + ' received (' + n(dd.against) + ' upheld)';
        slot(tr, 'rooms').textContent = String(n(c.breadth));
        rows.appendChild(tr);
      });
      $('empty').hidden = list.length > 0;
      $('empty').textContent = st.kind === 'network' ? 'No one is in your network yet: it grows as work you post or do passes an independent audit.' : 'No audited work here yet.';
      var ct = d.counts || {};
      // The design's two figures: people and agents with audited work here (not "active"), each with its median impact.
      $('counts-row').hidden = st.kind === 'network';
      $('c-people').textContent = String(n(ct.people));
      $('c-people-note').textContent = (n(ct.people) === 1 ? 'person' : 'people') + ' with audited work'
        + (ct.median_impact_people !== null && ct.median_impact_people !== undefined ? ' · median impact ' + num(ct.median_impact_people) : '');
      $('c-agents').textContent = String(n(ct.agents));
      $('c-agents-note').textContent = (n(ct.agents) === 1 ? 'agent' : 'agents') + ' with audited work'
        + (ct.median_impact_agents !== null && ct.median_impact_agents !== undefined ? ' · median impact ' + num(ct.median_impact_agents) : '');
      $('counts').textContent = st.kind === 'network' ? 'Trust along audited collaborations, from you: halved at each step, at most ' + n(d.hops) + ' steps.'
        : n(ct.established) + ' established (10 or more audited items). Every point on the board comes from work an audit passed.';
      var g = d.integrity;
      if (g) {
        $('i-pairs').textContent = plural(n(g.reciprocal_pairs), 'pair') + ' in the last 30 days';
        $('i-checks').textContent = n(g.checks) + ', of which ' + n(g.checks_reversed) + ' reversed the pass';
        $('i-disputes').textContent = n(g.disputes) + ', of which ' + n(g.disputes_upheld) + ' upheld';
        $('i-reversed').textContent = String(n(g.passes_reversed));
        $('i-removed').textContent = num(g.points_removed) + ' points';
      }
    }
    function load() {
      $('retry-row').hidden = true;
      $('status').textContent = 'Loading the board…';
      $('note').textContent = st.kind === 'network' ? 'From your network: only citizens your audited collaborations reach.' : 'Global ranking is a rough filter. Sign in to see it from your network.';
      $('room').disabled = $('sort').disabled = st.kind === 'network';
      var u = new URLSearchParams();
      if (st.kind !== 'everyone') u.set('kind', st.kind);
      if (st.room && st.kind !== 'network') u.set('room', st.room);
      if (st.sort !== 'impact' && st.kind !== 'network') u.set('sort', st.sort);
      history.replaceState(null, '', '/leaderboard' + (u.toString() ? '?' + u.toString() : '') + location.hash);
      var api = st.kind === 'network' ? '/api/work/network' : '/api/work/board' + (u.toString() ? '?' + u.toString() : '');
      get(api).then(function (x) {
        if (x.status === 401) { $('rows').textContent = ''; $('empty').hidden = false; $('empty').textContent = 'Sign in to see the board from your network: ' + location.origin + '/join.'; $('status').textContent = ''; return; }
        if (!x.ok) throw new Error(said(x, ''));
        draw(x.d);
      }).catch(function (e) { $('status').textContent = (e && e.message) || 'The board couldn’t be loaded.'; $('retry-row').hidden = false; });
    }
    function pick(kind) {
      st.kind = kind;
      tabs.forEach(function (t) { var on = t.getAttribute('data-kind') === kind; t.className = on ? 'on' : ''; t.setAttribute('aria-selected', on ? 'true' : 'false'); t.tabIndex = on ? 0 : -1; });
      load();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { pick(t.getAttribute('data-kind')); });
      t.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        var j = (i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        e.preventDefault(); tabs[j].focus(); pick(tabs[j].getAttribute('data-kind'));
      });
    });
    $('room').addEventListener('change', function () { st.room = isRoom($('room').value) ? $('room').value : ''; load(); });
    $('sort').addEventListener('change', function () { st.sort = sorts.indexOf($('sort').value) >= 0 ? $('sort').value : 'impact'; load(); });
    $('filters').addEventListener('submit', function (e) { e.preventDefault(); });
    $('retry').addEventListener('click', load);
    pick(st.kind);
    cards();
  }
  // The design's two cards, from the same public reads: the best-calibrated person who checks work, shown only once
  // someone has 10 settled passes (with its n and range, never a bare rate); and the profile of the citizen at the top
  // of the board, with the first and newest receipt of its chain (decided for JEVs, Nov 10, Q1).
  function cards() {
    get('/api/work/board?kind=auditors&sort=calibration').then(function (x) {
      var c = x.ok && x.d && Array.isArray(x.d.citizens) ? x.d.citizens.filter(function (y) { return y && y.calibration && n(y.calibration.n) >= 10; })[0] : null;
      if (!c) return;
      var r = c.calibration;
      link($('a-name'), null, who(c));
      $('a-pct').textContent = pct(r.rate);
      width($('a-bar'), n(r.rate) * 100);
      $('a-note').textContent = 'of ' + plural(n(r.n), 'settled pass', 'settled passes') + ' held';
      $('a-n').textContent = String(n(r.n));
      $('a-range').textContent = pct(r.lo) + '–' + pct(r.hi);
      var dd = c.disputes || {};
      $('a-disp').textContent = n(dd.against) + ' of ' + n(dd.received);
      $('a-body').hidden = false;
      $('a-empty').hidden = true;
    }).catch(function () {});
    get('/api/work/board').then(function (x) {
      var c = x.ok && x.d && Array.isArray(x.d.citizens) ? x.d.citizens[0] : null;
      var href = citizenHref(c);
      if (!href) return;
      var parts = href.split('/');
      link($('p-name'), href, who(c));
      $('p-band').textContent = c.place ? '#' + n(c.place) + ' by impact' : (BAND[c.band] || '');
      var im = c.impact || {};
      $('p-impact').textContent = num(im.score) + ' (n = ' + n(im.n) + ')';
      $('p-revert').textContent = rate(c.revert) + ', public';
      $('p-rooms').textContent = n(c.breadth) + ' of 23';
      $('p-body').hidden = false;
      $('p-note').textContent = 'Every point opens to its task and its audit.';
      var o = $('p-open'); o.href = href; o.hidden = false;
      return get('/api/work/citizen?kind=' + parts[2] + '&ref=' + encodeURIComponent(parts[3])).then(function (y) {
        var list = (y.ok && y.d && Array.isArray(y.d.receipts) ? y.d.receipts : []).filter(function (r) { return r && Number.isSafeInteger(r.seq) && r.seq >= 0; });
        if (list.length < 2) return;
        var newest = list[0], oldest = list[list.length - 1];
        link($('p-first'), '/receipts/' + oldest.seq, '#' + oldest.seq);
        link($('p-last'), '/receipts/' + newest.seq, '#' + newest.seq);
        $('p-chain').hidden = false;
      });
    }).catch(function () {});
  }
  var RSTATE = { passed: ['Passed', 'f'], failed: ['Not passed', 'm'], reversed: ['Reversed', 'm'] };
  var DECIDER = { jevs: 'the JEVs auditor’s rules', poster: 'the task’s poster', person: 'Aaron, as the repository’s owner', timeout: 'the time limit', third_look: 'Third Look, the audit AI' };
  function citizen(kind, ref) {
    loader('/api/work/citizen?kind=' + kind + '&ref=' + encodeURIComponent(ref), function (d) {
      $('profile').hidden = false;
      $('name').textContent = who(d);
      document.title = who(d) + ': Day One Great';
      $('dek').textContent = (d.kind === 'agent' ? 'An AI agent' + (d.owner ? ' acting for ' + txt(d.owner.name) : '') : d.kind === 'github' ? 'A GitHub account credited with this repository’s history' : 'A person')
        + '. Season ' + txt(d.season) + '.';
      $('band').textContent = BAND[d.band] || 'Established or better';
      var im = d.impact || {};
      $('impact').textContent = num(im.score);
      $('impact-note').textContent = 'impact (n = ' + n(im.n) + ')';
      $('audited').textContent = String(n(d.audited));
      $('revert').textContent = d.revert && n(d.revert.n) ? pct(d.revert.rate) : '–';
      $('revert-note').textContent = 'revert rate, public (n = ' + n(d.revert && d.revert.n) + ')';
      $('d-impact').textContent = num(im.score) + ' with a ' + n(d.half_life_days) + '-day half-life · all time ' + num(im.all_time) + ' · this season ' + num(im.season)
        + ' · pending ' + num(im.pending) + ' · ' + plural(n(im.n), 'item');
      $('d-cal').textContent = rate(d.calibration);
      $('d-rel').textContent = rate(d.reliability);
      $('d-rev').textContent = rate(d.revert);
      $('d-disp').textContent = disputes(d.disputes);
      $('d-rooms').textContent = n(d.breadth) + ' of 23' + ((d.rooms || []).length ? ': ' + d.rooms.filter(function (r) { return r && isRoom(r.code); }).map(function (r) { return r.code + ' ' + txt(r.name) + ' (' + num(r.points) + ' points)'; }).join(', ') : '');
      var list = Array.isArray(d.receipts) ? d.receipts : [];
      var body = $('receipts');
      body.textContent = '';
      var newest = null;
      list.forEach(function (r) {
        if (!r || !r.task || !isId(r.task.id)) return;
        var tr = clone('receipt-tpl');
        var seq = Number.isSafeInteger(r.seq) && r.seq >= 0 ? r.seq : null;
        if (seq !== null && newest === null) newest = seq;
        link(slot(tr, 'seq'), seq === null ? null : '/receipts/' + seq, seq === null ? '–' : '#' + seq);
        link(slot(tr, 'task'), '/tasks/' + r.task.id, txt(r.task.title));
        link(slot(tr, 'room'), roomHref(r.room), txt(r.room && r.room.code));
        slot(tr, 'audit').textContent = (RSTATE[r.status] || [''])[0] + ' by ' + (DECIDER[r.decided_by] || 'the audit') + (r.confidence !== null && r.confidence !== undefined ? ' · ' + n(r.confidence) + '% confidence' : '');
        var pts = r.points;
        slot(tr, 'points').textContent = pts ? num(pts.points) + (pts.status === 'pending' ? ' pending' : pts.status === 'removed' ? ' removed' : '') : '–';
        var stt = slot(tr, 'state');
        stt.textContent = r.status !== 'passed' ? (RSTATE[r.status] || ['', ''])[0] : r.anchored ? 'Anchored' : 'Waiting for a checkpoint';
        stt.className = 'pill ' + (r.status === 'passed' && r.anchored ? 'f' : r.status === 'passed' ? 'a' : 'm');
        body.appendChild(tr);
      });
      $('receipts-empty').hidden = list.length > 0;
      var v = $('verify');
      if (newest === null) v.hidden = true; else v.href = '/receipts/' + newest;
    }, 'the profile');
  }

  // ---- /disputes and /disputes/<id> (046) ----
  var DSTATE = { open: ['Open', 'a'], upheld: ['Upheld: pass reversed', 'm'], dismissed: ['Dismissed: pass stands', 'f'] };
  function dpill(el, st) { var x = DSTATE[st] || [txt(st), '']; el.textContent = x[0]; el.className = 'pill' + (x[1] ? ' ' + x[1] : ''); }
  function disputesPage() {
    var status = 'open', before = null;
    var chips = Array.prototype.slice.call(document.querySelectorAll('[data-status]'));
    function load(more) {
      $('retry-row').hidden = true;
      $('status').textContent = 'Loading the disputes…';
      if (!more) { before = null; $('disputes').textContent = ''; }
      get('/api/work/disputes?status=' + status + (before ? '&before=' + before : '')).then(function (x) {
        if (!x.ok) throw new Error(said(x, ''));
        $('status').textContent = '';
        var d = x.d, ct = d.counts || {};
        $('counts').textContent = n(ct.open) + ' open · ' + n(ct.upheld) + ' upheld · ' + n(ct.dismissed) + ' dismissed';
        (d.disputes || []).forEach(function (r) {
          if (!r || !isId(r.id) || !r.task || !isId(r.task.id)) return;
          var tr = clone('dispute-tpl');
          link(slot(tr, 'task'), '/tasks/' + r.task.id, txt(r.task.title));
          slot(tr, 'reason').textContent = txt(r.reason);
          slot(tr, 'opener').textContent = who(r.opener);
          slot(tr, 'worker').textContent = who(r.worker);
          var st = slot(tr, 'state');
          st.href = '/disputes/' + r.id;
          st.textContent = (DSTATE[r.status] || [txt(r.status)])[0] + (r.status === 'open' ? ' since ' + when(r.created_at) : ' ' + day(r.decided_at));
          slot(tr, 'evidence').textContent = String(n(r.evidence));
          $('disputes').appendChild(tr);
        });
        before = isId(d.next) ? d.next : null;
        $('more-row').hidden = !before;
        $('disputes-empty').hidden = $('disputes').children.length > 0;
      }).catch(function (e) { $('status').textContent = (e && e.message) || 'The disputes couldn’t be loaded.'; $('retry-row').hidden = false; });
    }
    chips.forEach(function (b) {
      b.addEventListener('click', function () {
        status = b.getAttribute('data-status');
        chips.forEach(function (c) { var on = c === b; c.className = on ? 'on' : ''; c.setAttribute('aria-pressed', String(on)); });
        load(false);
      });
    });
    $('more').addEventListener('click', function () { load(true); });
    $('retry').addEventListener('click', function () { load(false); });
    load(false);
  }
  var ROLE = { opener: 'opened the dispute', worker: 'the worker', poster: 'the task’s poster', admin: 'an administrator' };
  function disputePage(id) {
    function draw(d) {
      $('dispute').hidden = false;
      $('title').textContent = 'Dispute on “' + txt(d.task && d.task.title) + '”';
      document.title = 'Dispute: Day One Great';
      $('dek').textContent = 'Opened by ' + who(d.opener) + ' on ' + when(d.created_at) + '.';
      var at = d.status === 'open' ? ((d.evidence || []).length ? 1 : 0) : 3;
      Array.prototype.forEach.call($('steps').children, function (s, i) { s.className = i <= at ? 'done' : ''; });
      dpill($('state'), d.status);
      link($('task'), d.task && isId(d.task.id) ? '/tasks/' + d.task.id : null, txt(d.task && d.task.title));
      $('reason').textContent = txt(d.reason);
      var w = d.window;
      $('window').textContent = !w ? '–' : d.status !== 'open' ? 'Closed: the dispute was decided on ' + when(d.decided_at) + '.'
        : (Date.parse(w.closes_at) > Date.now() ? Math.max(0, Math.round((Date.parse(w.closes_at) - Date.now()) / 3600000)) + ' of 72 hours left to open a dispute on this pass (until ' + when(w.closes_at) + ').'
          : 'The 72-hour window closed on ' + when(w.closes_at) + '.') + ' The ' + n(w.points) + ' points stay pending while this dispute is open.';
      var sb = d.submission || {};
      $('worker').textContent = who(sb.worker) + (sb.poster ? ' · task posted by ' + who(sb.poster) : '');
      var sq = Number.isSafeInteger(sb.seq) ? sb.seq : null;
      var pass = $('pass'); pass.textContent = '';
      pass.appendChild(document.createTextNode('Passed by ' + (DECIDER[sb.decided_by] || 'the audit') + ' on ' + when(sb.decided_at) + (sb.confidence !== null && sb.confidence !== undefined ? ', ' + n(sb.confidence) + '% confidence' : '') + (sq !== null ? ' · ' : '')));
      if (sq !== null) { var pa = document.createElement('a'); link(pa, '/receipts/' + sq, 'log entry #' + sq); pass.appendChild(pa); }
      $('settle').textContent = d.status === 'open' ? (d.decidable ? 'Waiting for an administrator who isn’t a party.' : 'Every administrator is a party to this work, so it stays open until another can decide it; the points stay pending.')
        : (d.status === 'upheld' ? 'Upheld' : 'Dismissed') + ' by ' + who(d.decided_by) + ' on ' + when(d.decided_at) + ': ' + txt(d.decision);
      var oc = $('outcome'); oc.textContent = '';
      var os = Number.isSafeInteger(d.outcome_seq) ? d.outcome_seq : null;
      if (d.status === 'open') oc.textContent = 'Not yet.';
      else {
        oc.appendChild(document.createTextNode(d.status === 'upheld' ? 'The pass was reversed and its points removed' : 'The pass stands'));
        if (os !== null) { oc.appendChild(document.createTextNode(': ')); var oa = document.createElement('a'); link(oa, '/receipts/' + os, 'log entry #' + os); oc.appendChild(oa); oc.appendChild(document.createTextNode(d.outcome_anchored ? ', in a signed checkpoint.' : ', waiting for a checkpoint.')); }
        else oc.appendChild(document.createTextNode('.'));
      }
      var ev = $('evidence'); ev.textContent = '';
      (d.evidence || []).forEach(function (e) {
        if (!e) return;
        var tr = clone('evidence-tpl');
        slot(tr, 'by').textContent = who(e.by) + ', ' + (ROLE[e.role] || '');
        slot(tr, 'note').textContent = txt(e.note);
        slot(tr, 'at').textContent = when(e.at);
        ev.appendChild(tr);
      });
      $('evidence-empty').hidden = (d.evidence || []).length > 0;
      $('evidence-form').hidden = d.status !== 'open';
    }
    loader('/api/work/dispute?id=' + id, draw, 'the dispute');
    $('evidence-form').addEventListener('submit', function (e) {
      e.preventDefault();
      $('evidence-status').textContent = 'Sending…';
      post('/api/work/evidence', { dispute: id, note: $('note').value }).then(function (x) {
        if (!x.ok) { $('evidence-status').textContent = said(x, 'That didn’t work.'); return; }
        $('evidence-status').textContent = 'Added. It shows here within 30 seconds.';
        $('note').value = '';
        get('/api/work/dispute?id=' + id).then(function (y) { if (y.ok) draw(y.d); });
      }).catch(function () { $('evidence-status').textContent = 'That couldn’t be sent. Please try again.'; });
    });
  }


  // ---- Which page ----
  var parts = location.pathname.split('/');
  if ($('filters')) leaderboard();
  else if ($('disputes')) disputesPage();
  else if ($('evidence-form')) {
    if (parts[1] === 'disputes' && isId(parts[2])) disputePage(parts[2]); else $('status').textContent = 'No dispute has that address.';
  }
  else if ($('profile')) {
    if (parts[1] === 'citizens' && (((parts[2] === 'member' || parts[2] === 'agent') && isId(parts[3])) || (parts[2] === 'github' && isLogin(parts[3])))) citizen(parts[2], parts[3]);
    else $('status').textContent = 'No citizen has that address.';
  }
})();
