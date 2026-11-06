// The work pages (042; the design handoff of Nov 5, 2026): /build, /tasks/<id>, /rooms, /rooms/<code>, /projects and
// /projects/<id>, from the work module's API (/api/work/*). One script for the six: each page has its own ids, and only
// the matching part runs. Every name and word anyone wrote is drawn with textContent, never as HTML; every link goes
// to our own pages or to this repository on GitHub; IDs and codes are checked character by character, so no pattern
// runs over what an address or an answer holds. Signed-in steps (claim, submit, approve, post) send JSON to our own
// API, which decides; this page only shows what it said.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  var HEX = '0123456789abcdef';
  function isId(x) {
    if (typeof x !== 'string' || x.length !== 36) return false;
    for (var i = 0; i < 36; i++) { var ch = x.charAt(i); if ((i === 8 || i === 13 || i === 18 || i === 23) ? ch !== '-' : HEX.indexOf(ch) < 0) return false; }
    return true;
  }
  function isRoom(x) {
    if (typeof x !== 'string' || x.length !== 7 || x.slice(2) !== '-0000') return false;
    return '0123456789'.indexOf(x.charAt(0)) >= 0 && '0123456789'.indexOf(x.charAt(1)) >= 0;
  }
  var REPO = 'https://github.com/MyChiefOS/start-of-something-great/';
  function safeUrl(u) { return typeof u === 'string' && u.indexOf(REPO) === 0 && u.length < 120 ? u : null; }
  function slot(node, name) { return node.querySelector('[data-slot="' + name + '"]'); }
  function clone(id) { return $(id).content.firstElementChild.cloneNode(true); }
  function txt(x) { return x === null || x === undefined ? '' : String(x); }
  function n(x) { var v = Number(x); return Number.isFinite(v) ? v : 0; }
  function plural(k, one, many) { return k === 1 ? '1 ' + one : k + ' ' + (many || one + 's'); }
  function width(el, pct) { var w = Math.max(0, Math.min(100, Math.round(n(pct) / 5) * 5)); el.className = 'w' + w; }
  function day(s) { return typeof s === 'string' ? s.slice(0, 10) : ''; }
  function when(s) { return typeof s === 'string' ? s.slice(0, 16).replace('T', ' ') + ' UTC' : ''; }
  var STATE = { open: ['Open', ''], claimed: ['Claimed', 'a'], submitted: ['Submitted', 'a'], audited: ['Audited', 'a'], approved: ['Approved', 'f'], closed: ['Closed', 'm'] };
  var CLASS = { agent: 'Agent', person: 'Person', either: 'Either' };
  var CLASS_TEXT = { agent: 'Only an AI agent may claim it, acting for its owner.', person: 'Only a person may claim it.', either: 'A person or an AI agent may claim it.' };
  function pill(el, state) { var s = STATE[state] || [txt(state), '']; el.textContent = s[0]; el.className = 'pill' + (s[1] ? ' ' + s[1] : ''); }
  // A citizen as the API names them: a member, an agent with its owner, or a GitHub login.
  function who(c) {
    if (!c || typeof c !== 'object') return '';
    if (c.kind === 'agent') return txt(c.name) + (c.owner ? ', for ' + txt(c.owner.name) : '');
    return txt(c.name);
  }
  function whoEl(c) {
    var span = document.createElement('span');
    if (!c) { var i = document.createElement('i'); i.textContent = 'Unclaimed'; span.className = 'fine'; span.appendChild(i); return span; }
    span.textContent = who(c) + ' ';
    var p = document.createElement('span');
    p.className = 'pill m';
    p.textContent = c.kind === 'agent' ? 'Agent' : c.kind === 'github' ? 'GitHub' : 'Person';
    span.appendChild(p);
    return span;
  }
  function link(el, href, text) { el.textContent = text; if (href) el.href = href; else el.removeAttribute('href'); }
  function taskHref(t) { return t && isId(t.id) ? '/tasks/' + t.id : null; }
  function projectHref(p) { return p && isId(p.id) ? '/projects/' + p.id : null; }
  function roomHref(r) { return r && isRoom(r.code) ? '/rooms/' + r.code : null; }

  function get(path) {
    return fetch(path, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }, function () { return { ok: false, status: r.status, d: {} }; }); });
  }
  function post(path, body) {
    return fetch(path, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }, function () { return { ok: false, status: r.status, d: {} }; }); });
  }
  function said(x, fallback) {
    var e = x && x.d && typeof x.d.error === 'string' ? x.d.error : fallback;
    if (x && x.status === 401) return 'Sign in first: ' + location.origin + '/join. ' + e;
    return e;
  }
  // Loads once, with "Try again" on failure.
  function loader(path, draw, label) {
    function load() {
      $('retry-row').hidden = true;
      $('status').textContent = 'Loading ' + label + '…';
      get(path).then(function (x) {
        if (x.status === 404) { $('status').textContent = said(x, 'Not found.'); return; }
        if (!x.ok) throw new Error(said(x, ''));
        $('status').textContent = '';
        draw(x.d);
      }).catch(function (e) {
        $('status').textContent = (e && e.message) || ('The ' + label + ' couldn’t be loaded.');
        $('retry-row').hidden = false;
      });
    }
    $('retry').addEventListener('click', load);
    load();
  }

  // ---- /build ----
  function build(d) {
    var total = n(d.tasks), anchored = n(d.anchored);
    var pct = total ? Math.floor((100 * anchored) / total) : 0;
    $('pct').textContent = pct + '%';
    width($('pct-bar'), pct);
    $('pct-note').textContent = plural(n(d.projects), 'open project') + ' · ' + plural(total, 'task') + ' · ' + anchored + ' approved and in a signed checkpoint · '
      + n(d.open) + ' open, ' + n(d.in_progress) + ' in progress' + (n(d.waiting_for_person) ? ' · ' + n(d.waiting_for_person) + ' waiting for Aaron' : '');
    var pk = $('packages');
    pk.textContent = '';
    (d.packages || []).forEach(function (p) {
      if (!p || !isId(p.id)) return;
      var row = clone('pkg-tpl');
      slot(row, 'room').textContent = txt(p.room && p.room.code);
      link(slot(row, 'title'), projectHref(p), txt(p.title));
      slot(row, 'by').textContent = who(p.poster);
      width(slot(row, 'bar'), p.percent);
      slot(row, 'pct').textContent = n(p.percent) + '%';
      var st = slot(row, 'state');
      if (n(p.tasks) > 0 && n(p.approved) === n(p.tasks)) pill(st, 'approved'); else if (n(p.claimed) + n(p.submitted) > 0) { st.textContent = 'In progress'; st.className = 'pill a'; } else pill(st, 'open');
      pk.appendChild(row);
    });
    $('packages-empty').hidden = pk.children.length > 0;
    // The chart: six weeks, scope and verified, on the same scale.
    var weeks = Array.isArray(d.weeks) ? d.weeks.slice(-6) : [];
    var top = Math.max(1, Math.max.apply(null, weeks.map(function (w) { return n(w.scope); }).concat([1])));
    // Six points from x 30 to 500, the last one "now"; y from 230 (none) to 20 (the most).
    var off = 6 - weeks.length;
    function pts(key) { return weeks.map(function (w, i) { return (30 + 94 * (i + off)) + ',' + Math.round(230 - (210 * n(w[key])) / top); }).join(' '); }
    $('scope').setAttribute('points', pts('scope'));
    $('verified').setAttribute('points', pts('verified'));
    $('y-max').textContent = String(top);
    $('y-mid').textContent = String(Math.round(top / 2));
    weeks.slice(0, 5).forEach(function (w, i) { var el = $('w' + (i + 1)); if (el) el.textContent = day(w.week).slice(5); });
    var last = weeks[weeks.length - 1] || {};
    $('chart-text').textContent = 'This week: ' + plural(n(last.scope), 'task') + ' in scope, ' + n(last.verified) + ' verified.';
    // The latest receipt.
    var r = d.latest_receipt;
    $('receipt').hidden = !r;
    $('receipt-empty').hidden = !!r;
    if (r) {
      $('r-anchor').textContent = r.anchored ? 'Anchored' : 'Waiting for a checkpoint';
      $('r-anchor').className = r.anchored ? 'pill f' : 'pill a';
      $('r-ref').textContent = 'Entry ' + n(r.seq);
      $('r-task').textContent = txt(r.task && r.task.ref) + ' · ' + txt(r.task && r.task.title);
      $('r-worker').textContent = who(r.worker);
      var a = r.artifact || {};
      $('r-artifact').textContent = a.kind === 'pr' ? 'A pull request in this repository' : a.kind === 'link' ? 'A link' : 'A file, by its SHA-256';
      $('r-audit').textContent = ({ jevs: 'The JEVs auditor’s rules', poster: 'The task’s poster', person: 'Aaron, as the repository’s owner' }[r.decided_by] || 'The audit') + ', ' + n(r.confidence) + '% confidence';
      $('r-points').textContent = r.points === null || r.points === undefined ? '–' : n(r.points) + ' (no money value)';
      $('r-approved').textContent = r.approved_seq === null || r.approved_seq === undefined ? 'Waiting for the poster' : 'Entry ' + n(r.approved_seq);
      $('r-open').href = '/receipts/' + n(r.seq);
    }
    // The board.
    var b = $('board');
    b.textContent = '';
    (d.board || []).forEach(function (t) {
      if (!t || !isId(t.id)) return;
      var tr = clone('row-tpl');
      slot(tr, 'ref').textContent = txt(t.ref);
      link(slot(tr, 'title'), taskHref(t), txt(t.title));
      slot(tr, 'who').appendChild(whoEl(t.done_by || t.worker));
      pill(slot(tr, 'state'), t.status);
      var rc = slot(tr, 'receipt');
      if (t.receipt !== null && t.receipt !== undefined) { var ra = document.createElement('a'); ra.href = '/receipts/' + n(t.receipt); ra.textContent = 'Entry ' + n(t.receipt); rc.appendChild(ra); }
      else if (t.status === 'open') { var ca = document.createElement('a'); ca.className = 'btn s'; ca.href = taskHref(t); ca.textContent = 'Claim'; rc.appendChild(ca); }
      else { rc.className = 'fine'; rc.textContent = 'pending'; }
      b.appendChild(tr);
    });
    $('board-empty').hidden = b.children.length > 0;
    // Live: the work's latest log entries.
    var LIVE = { 'task.claimed': 'claimed a task', 'task.submitted': 'submitted work', 'audit.verdict': 'checked a submission', 'task.approved': 'approved a task' };
    var lv = $('live');
    lv.textContent = '';
    (d.live || []).forEach(function (e) {
      if (!e || !LIVE[e.type]) return;
      var row = clone('live-tpl');
      slot(row, 'at').textContent = when(e.at);
      var actor = txt(e.actor);
      slot(row, 'kind').textContent = actor.indexOf('agent:') === 0 ? 'Agent' : actor.indexOf('github:') === 0 ? 'GitHub' : actor.indexOf('member:') === 0 ? 'Person' : 'Audit';
      var by = actor === 'jevs-audit' ? 'The JEVs auditor’s rules' : actor === 'work-audit' ? null : actor.indexOf('github:') === 0 ? '@' + actor.slice(7) : 'Someone';
      slot(row, 'text').textContent = (by ? by + ' ' + LIVE[e.type] : 'An audit’s outcome and points were recorded') + ' (entry ' + n(e.seq) + ')';
      var an = slot(row, 'anchor');
      an.textContent = e.anchored ? 'Anchored' : 'Pending';
      if (e.anchored) an.className = 'pill a';
      lv.appendChild(row);
    });
    $('live-empty').hidden = lv.children.length > 0;
  }

  // ---- /tasks/<id> ----
  function task(id) {
    var t = null, checkable = null, mine = null;
    // The poster's check: shown when the signed-in person is this task's poster and work waits for their check.
    function showCheck() {
      $('check-form').hidden = !(checkable && mine && mine.indexOf(checkable) >= 0);
    }
    get('/api/work/mine').then(function (x) { if (x.ok && Array.isArray(x.d.to_check)) { mine = x.d.to_check.map(function (c) { return c.submission; }); showCheck(); } }).catch(function () {});
    function draw(d) {
      checkable = null;
      t = d;
      $('task').hidden = false;
      $('title').textContent = txt(d.title);
      document.title = txt(d.title).slice(0, 80) + ': Day One Great';
      $('crumb-ref').textContent = txt(d.ref);
      link($('crumb-project'), projectHref(d.project), txt(d.project && d.project.title));
      $('dek').textContent = txt(d.ref) + ' in ' + txt(d.project && d.project.title) + '.';
      var order = ['open', 'claimed', 'submitted', 'audited', 'approved', 'anchored'];
      var at = d.status === 'approved' && d.approved_seq !== null && n(d.approved_seq) < n(d.anchored_through) ? 5 : order.indexOf(d.status);
      Array.prototype.forEach.call($('steps').children, function (s, i) { s.className = i <= at ? 'done' : ''; });
      $('class').textContent = CLASS[d.class] || txt(d.class);
      pill($('state'), d.status);
      $('size').textContent = 'Size ' + n(d.size);
      $('description').textContent = txt(d.description);
      link($('project'), projectHref(d.project), txt(d.project && d.project.title));
      link($('room'), roomHref(d.room), txt(d.room && d.room.code) + ' ' + txt(d.room && d.room.name));
      $('poster').textContent = who(d.poster);
      $('class-text').textContent = CLASS_TEXT[d.class] || '';
      $('claim').textContent = d.claim ? 'Claimed by ' + who(d.claim.by) + ' until ' + when(d.claim.expires_at) + '.' : 'Holds for 72 hours, then reopens if nothing is submitted.';
      var gh = safeUrl(d.url);
      $('github').textContent = '';
      if (gh) { var a = document.createElement('a'); a.href = gh; a.rel = 'noopener'; a.textContent = txt(d.ref) + ' on GitHub'; $('github').appendChild(a); } else $('github').textContent = 'Posted on this site';
      $('claim-btn').hidden = d.status !== 'open';
      $('submit-form').hidden = d.status !== 'claimed';
      $('release-btn').hidden = d.status !== 'claimed';
      $('approve-btn').hidden = d.status !== 'audited';
      $('cancel-btn').hidden = d.status !== 'open' || d.source !== 'member';
      var subs = $('subs');
      subs.textContent = '';
      (d.submissions || []).forEach(function (s) {
        var c = clone('sub-tpl');
        slot(c, 'meta').textContent = 'Submission · ' + who(s.worker) + ' · ' + when(s.created_at);
        var art = s.artifact || {};
        var as = slot(c, 'artifact');
        if (art.kind === 'pr' && safeUrl(art.url)) { var pa = document.createElement('a'); pa.href = art.url; pa.rel = 'noopener'; pa.textContent = 'Pull request #' + n(art.pr); as.appendChild(pa); }
        else if (art.kind === 'link') as.textContent = 'Link (not opened by this page): ' + txt(art.url);
        else as.textContent = 'File, SHA-256 ' + txt(art.sha256);
        slot(c, 'note').textContent = txt(s.note);
        var j = s.jevs || {};
        slot(c, 'jevs').textContent = j.verdict ? { pass: 'Passed', fail: 'Refused', person: 'Sent to a person', waiting: 'Waiting for GitHub' }[j.verdict] + (j.rules ? ' (rules ' + j.rules + ')' : '') : 'Not yet';
        slot(c, 'decided').textContent = s.status === 'passed' || s.status === 'failed'
          ? (s.status === 'passed' ? 'Passed' : 'Not passed') + ' by ' + ({ jevs: 'the JEVs auditor’s rules', poster: 'the task’s poster', person: 'Aaron, as the repository’s owner' }[s.decided_by] || 'the audit') + ' · ' + txt(s.reason)
            + (s.check ? ' · Checked again: ' + ({ open: 'waiting', confirmed: 'confirmed', reversed: 'reversed' }[s.check.status] || '') : '')
          : s.status === 'reversed' ? 'Reversed: ' + txt(s.reason)
          : s.route === 'poster' ? 'Waiting for the task’s poster to check it.' : s.route === 'admin' ? 'Waiting for Aaron, as the repository’s owner.'
          : s.route === 'held' ? 'Waiting for Third Look (not built yet): ' + txt(s.held_reason) : 'Waiting';
        var p = s.points;
        slot(c, 'points').textContent = p ? n(p.points) + ' = size ' + n(p.size) + ' × ' + n(p.confidence) + '% confidence × ' + n(p.independence) + '% independence · ' + (p.status === 'final' ? 'final' : 'pending until ' + when(p.final_at)) : '–';
        var seal = s.seal || {};
        slot(c, 'seal').textContent = txt(seal.seal);
        sealCheck(seal, slot(c, 'seal-check'));
        var log = slot(c, 'log');
        [['submitted', s.submitted_seq], ['decided', s.decided_seq]].forEach(function (x) {
          if (x[1] === null || x[1] === undefined) return;
          var l = document.createElement('a'); l.href = '/receipts/' + n(x[1]); l.textContent = x[0] + ': entry ' + n(x[1]);
          if (log.children.length) log.appendChild(document.createTextNode(' · '));
          log.appendChild(l);
        });
        var dl = slot(c, 'disputes');
        (s.disputes || []).forEach(function (x) {
          var pp = document.createElement('p'); pp.className = 'fine';
          pp.textContent = 'Dispute (' + ({ open: 'open: the points wait for Aaron', upheld: 'upheld: the pass was reversed', dismissed: 'dismissed' }[x.status] || '') + '): ' + txt(x.reason) + (x.decision ? ' · Decision: ' + txt(x.decision) : '');
          dl.appendChild(pp);
        });
        var open = s.status === 'passed' && s.points && s.points.status === 'pending' && !(s.disputes || []).some(function (x) { return x.status === 'open'; });
        var dw = slot(c, 'dispute-wrap');
        dw.hidden = !open;
        if (open && isId(s.id)) slot(c, 'dispute-send').addEventListener('click', function () {
          act('/api/work/dispute', { submission: s.id, reason: slot(c, 'dispute-reason').value }, function () { return 'Dispute sent. The points wait until Aaron decides it.'; });
        });
        if (s.route === 'poster' && s.status === 'review' && isId(s.id)) checkable = s.id;
        subs.appendChild(c);
      });
      showCheck();
      $('subs-empty').hidden = subs.children.length > 0;
    }
    // The seal is SHA-256 over its key and its facts (JSON, keys sorted): checked here, in the browser.
    function jcs(v) {
      if (v === null || typeof v !== 'object') return JSON.stringify(v);
      if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
      return '{' + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ':' + jcs(v[k]); }).join(',') + '}';
    }
    function sealCheck(seal, el) {
      if (!seal || !seal.key || !seal.facts || !window.crypto || !crypto.subtle) return;
      var key = new Uint8Array((String(seal.key).match(/../g) || []).map(function (h) { return parseInt(h, 16); }));
      var facts = new TextEncoder().encode(jcs(seal.facts));
      var all = new Uint8Array(key.length + facts.length);
      all.set(key); all.set(facts, key.length);
      crypto.subtle.digest('SHA-256', all).then(function (h) {
        var hex = Array.prototype.map.call(new Uint8Array(h), function (b) { return (b < 16 ? '0' : '') + b.toString(16); }).join('');
        el.textContent = hex === seal.seal ? 'Checked in your browser: the seal matches its key and facts.' : 'The seal doesn’t match its key and facts.';
      }).catch(function () {});
    }
    function act(path, body, ok) {
      $('act-status').textContent = 'Sending…';
      return post(path, body).then(function (x) {
        if (!x.ok) { $('act-status').textContent = said(x, 'That didn’t work.'); return null; }
        $('act-status').textContent = ok(x.d);
        // The answer carries the task as it now stands (the public read may be a cached copy up to 30 seconds old).
        if (x.d && x.d.task && x.d.task.id === id) draw(x.d.task);
        return x.d;
      }).catch(function () { $('act-status').textContent = 'That couldn’t be sent. Please try again.'; });
    }
    $('claim-btn').addEventListener('click', function () {
      act('/api/work/claim', { task: id }, function (d) { return 'Claimed until ' + when(d.expires_at) + '.'; }).then(function (d) {
        if (d && typeof d.code === 'string' && d.code.indexOf('dogw_') === 0 && d.code.length === 27) { $('code').textContent = d.code; $('code-card').hidden = false; }
      });
    });
    $('check-pass').addEventListener('click', function () {
      act('/api/work/check', { submission: checkable, verdict: 'pass', reason: $('check-reason').value.trim() || undefined }, function (d) { return txt(d.message) || 'Passed.'; });
    });
    $('check-fail').addEventListener('click', function () {
      act('/api/work/check', { submission: checkable, verdict: 'fail', reason: $('check-reason').value.trim() }, function (d) { return txt(d.message) || 'Not passed.'; });
    });
    $('release-btn').addEventListener('click', function () { act('/api/work/release', { task: id }, function () { return 'Your claim is let go; the task is open again.'; }); });
    $('approve-btn').addEventListener('click', function () { act('/api/work/approve', { task: id }, function () { return 'Approved. It counts once a signed checkpoint covers the approval.'; }); });
    $('cancel-btn').addEventListener('click', function () { act('/api/work/cancel', { task: id }, function () { return 'Closed.'; }); });
    $('kind').addEventListener('change', function () {
      var file = $('kind').value === 'file';
      $('url').hidden = file; $('url-label').hidden = file; $('sha').hidden = !file; $('sha-label').hidden = !file;
      $('url').placeholder = $('kind').value === 'pr' ? REPO + 'pull/123' : 'https://';
    });
    $('submit-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var kind = $('kind').value;
      var body = { task: id, kind: kind, note: $('note').value };
      if (kind === 'file') body.sha256 = $('sha').value.trim().toLowerCase(); else body.url = $('url').value.trim();
      act('/api/work/submit', body, function (d) { return txt(d.message) || 'Submitted.'; });
    });
    loader('/api/work/task?id=' + id, draw, 'the task');
  }

  // ---- /rooms ----
  function rooms() {
    var all = false, data = null;
    function draw() {
      var list = $('rooms');
      list.textContent = '';
      var quiet = [];
      (data.rooms || []).forEach(function (r) {
        if (!r || !isRoom(r.code)) return;
        if (!all && n(r.open) === 0) { quiet.push(txt(r.name)); return; }
        var a = clone('room-tpl');
        a.href = '/rooms/' + r.code;
        slot(a, 'code').textContent = r.code;
        slot(a, 'name').textContent = txt(r.name);
        slot(a, 'open').textContent = n(r.open) + ' open';
        list.appendChild(a);
      });
      $('rooms-empty').hidden = list.children.length > 0;
      $('quiet-wrap').hidden = all || quiet.length === 0;
      $('quiet-count').textContent = plural(quiet.length, 'room') + ' with no open tasks';
      $('quiet').textContent = quiet.join(' · ');
      $('show-open').className = all ? '' : 'on'; $('show-open').setAttribute('aria-pressed', String(!all));
      $('show-all').className = all ? 'on' : ''; $('show-all').setAttribute('aria-pressed', String(all));
    }
    $('show-open').addEventListener('click', function () { all = false; if (data) draw(); });
    $('show-all').addEventListener('click', function () { all = true; if (data) draw(); });
    loader('/api/work/rooms', function (d) { data = d; draw(); }, 'the rooms');
  }

  // ---- /rooms/<code> ----
  function room(code) {
    loader('/api/work/room?code=' + code, function (d) {
      $('room').hidden = false;
      $('name').textContent = txt(d.name);
      document.title = txt(d.name) + ': Day One Great';
      $('crumb-code').textContent = code;
      $('dek').textContent = 'Room ' + code + '. ' + plural(n(d.open), 'open task') + '.';
      var w = $('workers');
      w.textContent = '';
      (d.workers || []).forEach(function (c) {
        var tr = clone('worker-tpl');
        slot(tr, 'name').textContent = who(c);
        var k = slot(tr, 'kind');
        k.textContent = c.kind === 'agent' ? 'Agent' : c.kind === 'github' ? 'GitHub' : 'Person';
        k.className = c.kind === 'agent' ? 'pill a' : 'pill m';
        slot(tr, 'final').textContent = String(n(c.final));
        slot(tr, 'pending').textContent = String(n(c.pending));
        slot(tr, 'items').textContent = String(n(c.items));
        w.appendChild(tr);
      });
      $('workers-empty').hidden = w.children.length > 0;
      var p = $('projects');
      p.textContent = '';
      (d.projects || []).forEach(function (x) {
        if (!x || !isId(x.id)) return;
        var tr = clone('project-tpl');
        link(slot(tr, 'title'), projectHref(x), txt(x.title));
        slot(tr, 'poster').textContent = who(x.poster);
        slot(tr, 'open').textContent = String(n(x.open));
        p.appendChild(tr);
      });
      $('projects-empty').hidden = p.children.length > 0;
      $('post-here').href = '/projects?room=' + code + '#post';
    }, 'the room');
  }

  // ---- /projects ----
  function fillRooms(selects, chosen) {
    get('/api/work/rooms').then(function (x) {
      if (!x.ok) return;
      (x.d.rooms || []).forEach(function (r) {
        if (!r || !isRoom(r.code)) return;
        selects.forEach(function (s) { var o = document.createElement('option'); o.value = r.code; o.textContent = r.code + ' ' + txt(r.name); if (r.code === chosen) o.selected = true; s.appendChild(o); });
      });
    });
  }
  function projects() {
    var p = new URLSearchParams(location.search);
    var STATUSES = ['open', 'claimed', 'submitted', 'completed', 'all'];
    var status = STATUSES.indexOf(p.get('status')) >= 0 ? p.get('status') : 'open';
    var roomCode = isRoom(p.get('room')) ? p.get('room') : '';
    var q = (p.get('q') || '').slice(0, 100);
    var before = null;
    $('q').value = q;
    fillRooms([$('room'), $('p-room')], roomCode);
    Array.prototype.forEach.call($('chips').children, function (b) {
      b.className = b.getAttribute('data-status') === status ? 'on' : '';
      b.setAttribute('aria-pressed', String(b.getAttribute('data-status') === status));
      b.addEventListener('click', function () { go({ status: b.getAttribute('data-status') }); });
    });
    function go(change) {
      var s = change.status || status, r = change.room !== undefined ? change.room : roomCode, qq = change.q !== undefined ? change.q : q;
      var u = new URLSearchParams();
      if (s !== 'open') u.set('status', s);
      if (r) u.set('room', r);
      if (qq.length >= 2) u.set('q', qq);
      location.search = u.toString();
    }
    $('search').addEventListener('submit', function (e) { e.preventDefault(); go({ q: $('q').value.trim(), room: $('room').value }); });
    function path() {
      var u = new URLSearchParams();
      u.set('status', status);
      if (roomCode) u.set('room', roomCode);
      if (q.length >= 2) u.set('q', q);
      if (before) u.set('before', before);
      return '/api/work/projects?' + u.toString();
    }
    function draw(d, append) {
      var list = $('list');
      if (!append) list.textContent = '';
      (d.projects || []).forEach(function (x) {
        if (!x || !isId(x.id)) return;
        var tr = clone('row-tpl');
        link(slot(tr, 'title'), projectHref(x), txt(x.title));
        slot(tr, 'room').textContent = txt(x.room && x.room.code);
        slot(tr, 'poster').textContent = who(x.poster);
        var st = slot(tr, 'state');
        if (n(x.tasks) > 0 && n(x.approved) === n(x.tasks)) { st.textContent = 'Completed'; st.className = 'pill f'; }
        else if (n(x.submitted) > 0) pill(st, 'submitted'); else if (n(x.claimed) > 0) pill(st, 'claimed'); else pill(st, 'open');
        slot(tr, 'pct').textContent = n(x.percent) + '%';
        list.appendChild(tr);
      });
      var some = list.children.length > 0;
      $('list-wrap').hidden = !some;
      $('list-empty').hidden = some;
      $('list-empty').textContent = q ? 'No projects match "' + q + '". Try fewer words, or browse rooms at /rooms.' : 'No projects here yet. Post one below.';
      before = isId(d.next_before) ? d.next_before : null;
      $('more-row').hidden = !before;
    }
    $('more').addEventListener('click', function () { get(path()).then(function (x) { if (x.ok) draw(x.d, true); }); });
    loader(path(), function (d) { draw(d, false); }, 'the projects');
    $('post-form').addEventListener('submit', function (e) {
      e.preventDefault();
      $('post-status').textContent = 'Posting…';
      post('/api/work/projects', { title: $('p-title').value, description: $('p-desc').value, room: $('p-room').value }).then(function (x) {
        if (!x.ok || !isId(x.d.id)) { $('post-status').textContent = said(x, 'That couldn’t be posted.'); return; }
        location.href = '/projects/' + x.d.id + '#add';
      }).catch(function () { $('post-status').textContent = 'That couldn’t be sent. Please try again.'; });
    });
  }

  // ---- /projects/<id> ----
  function project(id) {
    function draw(d) {
      $('project').hidden = false;
      $('title').textContent = txt(d.title);
      document.title = txt(d.title).slice(0, 80) + ': Day One Great';
      $('crumb-id').textContent = txt(d.title).slice(0, 40);
      $('dek').textContent = 'Posted by ' + who(d.poster) + ' in ' + txt(d.room && d.room.code) + ' ' + txt(d.room && d.room.name) + '.';
      var done = n(d.tasks) > 0 && n(d.approved) === n(d.tasks);
      var at = done ? 3 : n(d.submitted) > 0 ? 2 : n(d.claimed) > 0 ? 1 : 0;
      Array.prototype.forEach.call($('steps').children, function (s, i) { s.className = i <= at ? 'done' : ''; });
      $('description').textContent = txt(d.description);
      $('pct').textContent = n(d.percent) + '%';
      width($('pct-bar'), d.percent);
      $('pct-note').textContent = n(d.approved) + ' of ' + plural(n(d.tasks), 'task') + ' approved · ' + n(d.open) + ' open';
      var l = d.latest;
      $('latest').hidden = !l;
      if (l) { $('latest-meta').textContent = 'Latest submission · ' + who(l.worker) + ' · ' + when(l.created_at) + ' · ' + txt(l.task && l.task.ref); $('latest-note').textContent = txt(l.note); }
      var tb = $('tasks');
      tb.textContent = '';
      (d.tasks || []).forEach(function (t) {
        if (!t || !isId(t.id)) return;
        var tr = clone('task-tpl');
        link(slot(tr, 'title'), taskHref(t), txt(t.title));
        slot(tr, 'ref').textContent = txt(t.ref);
        slot(tr, 'class').textContent = CLASS[t.class] || '';
        slot(tr, 'size').textContent = String(n(t.size));
        pill(slot(tr, 'state'), t.status);
        slot(tr, 'who').appendChild(whoEl(t.done_by || t.worker));
        tb.appendChild(tr);
      });
      $('tasks-empty').hidden = tb.children.length > 0;
      $('task-form').hidden = d.source !== 'member';
      $('add').hidden = d.source !== 'member';
    }
    $('task-form').addEventListener('submit', function (e) {
      e.preventDefault();
      $('task-status').textContent = 'Adding…';
      post('/api/work/tasks', { project: id, title: $('t-title').value, description: $('t-desc').value, class: $('t-class').value, size: Number($('t-size').value) }).then(function (x) {
        if (!x.ok || !isId(x.d.id)) { $('task-status').textContent = said(x, 'That couldn’t be added.'); return; }
        location.href = '/tasks/' + x.d.id;
      }).catch(function () { $('task-status').textContent = 'That couldn’t be sent. Please try again.'; });
    });
    loader('/api/work/project?id=' + id, draw, 'the project');
  }

  // ---- Which page ----
  var parts = location.pathname.split('/');
  if ($('packages')) {
    $('retry').addEventListener('click', function () { start(); });
    var start = function () {
      $('retry-row').hidden = true;
      get('/api/work/summary').then(function (x) {
        if (!x.ok) throw new Error(said(x, ''));
        build(x.d);
      }).catch(function (e) { $('pct-note').textContent = (e && e.message) || 'The work couldn’t be loaded.'; $('retry-row').hidden = false; });
    };
    start();
  } else if ($('subs')) {
    if (parts[1] === 'tasks' && isId(parts[2])) task(parts[2]); else $('status').textContent = 'No task has that address.';
  } else if ($('quiet')) rooms();
  else if ($('workers')) {
    if (parts[1] === 'rooms' && isRoom(parts[2])) room(parts[2]); else $('status').textContent = 'No room has that address.';
  } else if ($('post-form')) projects();
  else if ($('task-form')) {
    if (parts[1] === 'projects' && isId(parts[2])) project(parts[2]); else $('status').textContent = 'No project has that address.';
  }
})();
