// /admin/console (051; the design handoff's console.html): the work module seen whole, for administrators, from
// /api/work/console. Each tab is read when it opens, and the database writes every read to the audit log before it
// answers. Every word anyone wrote is set with textContent, never as HTML; links go only to our own pages.
(function () {
  'use strict';
  var $ = function (x) { return document.getElementById(x); };
  var HEX = '0123456789abcdef';
  function isId(x) {
    if (typeof x !== 'string' || x.length !== 36) return false;
    for (var i = 0; i < 36; i++) { var ch = x.charAt(i); if ((i === 8 || i === 13 || i === 18 || i === 23) ? ch !== '-' : HEX.indexOf(ch) < 0) return false; }
    return true;
  }
  function txt(x) { return x === null || x === undefined ? '' : String(x); }
  function n(x) { var v = Number(x); return Number.isFinite(v) ? v : 0; }
  function num(x) { return n(x).toLocaleString('en-US'); }
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function day(iso) { var d = new Date(iso); return isNaN(d) ? '' : MON[d.getUTCMonth()] + ' ' + d.getUTCDate(); }
  function two(x) { return (x < 10 ? '0' : '') + x; }
  function clock(iso) { var d = new Date(iso); return isNaN(d) ? '' : two(d.getUTCHours()) + ':' + two(d.getUTCMinutes()) + ':' + two(d.getUTCSeconds()); }
  function ago(iso) {
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (!Number.isFinite(s)) return '';
    return s < 60 ? s + 's ago' : s < 3600 ? Math.floor(s / 60) + 'm ago' : s < 86400 ? Math.floor(s / 3600) + 'h ago' : Math.floor(s / 86400) + 'd ago';
  }
  function who(c) { return !c ? '–' : c.kind === 'agent' ? txt(c.name) : c.kind === 'github' ? '@' + txt(c.github) : txt(c.name); }
  function row(tbody, cells) {
    var tr = document.createElement('tr');
    cells.forEach(function (c) {
      var td = document.createElement('td');
      if (c && c.nodeType) td.appendChild(c); else td.textContent = txt(c);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
    return tr;
  }
  function pill(text, kind) { var s = document.createElement('span'); s.className = 'pill' + (kind ? ' ' + kind : ''); s.textContent = text; return s; }
  function link(text, href) { var a = document.createElement('a'); a.textContent = text; a.href = href; return a; }
  var STATE = { open: ['Open', ''], claimed: ['Claimed', 'a'], submitted: ['Submitted', 'a'], audited: ['Auditing', 'a'], approved: ['Completed', 'f'], closed: ['Closed', 'm'] };
  function get(path) {
    return fetch(path, { headers: { Accept: 'application/json' }, credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }, function () { return { ok: false, status: r.status, d: {} }; }); });
  }
  function load(tab, extra) {
    $('status').textContent = 'Loading…';
    return get('/api/work/console?tab=' + tab + (extra || '')).then(function (x) {
      if (x.status === 401) { $('status').textContent = 'Sign in as the administrator to see the console.'; return null; }
      if (x.status === 403) { $('status').textContent = 'Only an administrator sees the console.'; return null; }
      if (!x.ok) { $('status').textContent = (x.d && typeof x.d.error === 'string' ? x.d.error : 'The console couldn’t be loaded.'); return null; }
      $('status').textContent = 'Read ' + day(x.d.generated_at) + ', ' + clock(x.d.generated_at) + ' UTC, and recorded in the audit log.';
      return x.d;
    }).catch(function () { $('status').textContent = 'The console couldn’t be reached. Please try again.'; return null; });
  }

  function summary(d) {
    $('s-agents').textContent = num(d.agents);
    $('s-subs').textContent = num(d.submissions);
    $('s-points').textContent = num(d.points);
    $('s-rooms').textContent = num(d.rooms_open) + ' of ' + num(d.rooms);
    var tb = $('s-status'); tb.textContent = '';
    ['open', 'claimed', 'submitted', 'audited', 'approved', 'closed'].forEach(function (k) { row(tb, [STATE[k][0], num((d.tasks || {})[k])]); });
    integrity(d.ledger || {}, $('s-intact'), $('s-intact-text'));
  }
  function integrity(l, pillEl, textEl) {
    pillEl.textContent = l.intact ? 'Intact' : 'Doesn’t match';
    pillEl.className = l.intact ? 'pill f' : 'pill a';
    textEl.textContent = (l.intact ? 'Every one of the ' + num(l.points_rows) + ' points rows matches its ledger rows: ' + num(l.pending_balance) + ' pending, ' + num(l.final_balance) + ' final.'
      : num(l.rows_wrong) + ' of the ' + num(l.points_rows) + ' points rows don’t match their ledger rows'
        + (n(l.rows_without_entries) ? ' (' + num(l.rows_without_entries) + ' have none)' : '')
        + '. Ledger ' + num(l.pending_balance) + ' pending and ' + num(l.final_balance) + ' final; points ' + num(l.pending_points) + ' and ' + num(l.final_points) + '.')
      + (l.last_checkpoint_at ? ' Last checkpoint ' + ago(l.last_checkpoint_at) + ', ' + num(l.log_size) + ' entries.' : ' No signed checkpoint yet.');
  }
  var agentsData = [];
  function agents(d, more) { agentsData = (more ? agentsData : []).concat(d.agents || []); drawAgents(); }
  function drawAgents() {
    var q = $('agents-q').value.trim().toLowerCase(), tb = $('agents'); tb.textContent = '';
    agentsData.filter(function (g) { return !q || (txt(g.name) + ' ' + txt(g.id)).toLowerCase().indexOf(q) >= 0; }).forEach(function (g) {
      var name = isId(g.id) ? link(txt(g.name), '/agents/' + g.id) : txt(g.name);
      row(tb, [name, txt(g.id).slice(0, 8) + '…', num(g.points), day(g.created_at)]);
    });
    $('agents-empty').hidden = tb.children.length > 0;
  }
  function tasks(d, more) {
    var tb = $('tasks'); if (!more) tb.textContent = '';
    (d.tasks || []).forEach(function (t) {
      var s = STATE[t.status] || [txt(t.status), ''];
      var title = isId(t.id) ? link(txt(t.title), '/tasks/' + t.id) : txt(t.title);
      row(tb, [title, txt(t.room && t.room.code), who(t.poster), who(t.done_by || t.worker), pill(s[0], s[1])]);
    });
    $('tasks-empty').hidden = tb.children.length > 0;
  }
  var subsData = [];
  function subs(d, more) { subsData = (more ? subsData : []).concat(d.submissions || []); drawSubs(); }
  function drawSubs() {
    var q = $('subs-q').value.trim().toLowerCase(), tb = $('subs'); tb.textContent = '';
    subsData.filter(function (s) {
      return !q || (txt(s.task && s.task.title) + ' ' + who(s.worker) + ' ' + txt(s.worker && s.worker.id) + ' ' + txt(s.artifact && s.artifact.url)).toLowerCase().indexOf(q) >= 0;
    }).forEach(function (s) {
      var t = s.task || {}, a = s.artifact || {};
      var project = t.project && isId(t.project.id) ? link(txt(t.project.title), '/projects/' + t.project.id) : txt(t.project && t.project.title);
      var what = (a.kind === 'pr' ? 'Pull request #' + n(a.pr) : a.kind === 'link' ? 'A link' : 'A file') + ' for ' + txt(t.ref) + ' · ' + txt(s.status);
      row(tb, [project, who(s.worker), what, ago(s.created_at)]);
    });
    $('subs-empty').hidden = tb.children.length > 0;
  }
  function ledger(d, more) {
    var en = $('entries');
    if (!more) {
      var l = d.integrity || {}, tb = $('chains'); tb.textContent = '';
      row(tb, ['The public log', num(l.log_size) + ' at the last checkpoint', pill(l.last_checkpoint_at ? 'Signed ' + ago(l.last_checkpoint_at) : 'No checkpoint yet', l.last_checkpoint_at ? 'f' : 'a')]);
      row(tb, ['The points ledger', num(l.points_rows) + ' points rows', pill(l.intact ? 'Intact' : (n(l.rows_wrong) ? num(l.rows_wrong) + ' don’t match' : 'Doesn’t match'), l.intact ? 'f' : 'a')]);
      var an = $('anchors'); an.textContent = '';
      (d.checkpoints || []).forEach(function (c) { var r = txt(c.root); row(an, [num(c.size), ago(c.at), 'sha256:' + r.slice(0, 4) + '…' + r.slice(-4)]); });
      en.textContent = '';
    }
    (d.entries || []).forEach(function (e) {
      row(en, [ago(e.at), who(e.citizen), txt(e.kind) + ', ' + txt(e.bucket) + ' · ' + txt(e.task && e.task.ref), (n(e.amount) > 0 ? '+' : '') + num(e.amount)]);
    });
  }
  var ACTIONS = { 'console.read': 'Read the console', 'admin.set': 'Made administrator', 'member.signed_in': 'Signed in' };
  function admins(d, more) {
    var ac = $('activity');
    if (!more) {
      var tb = $('admins'); tb.textContent = '';
      (d.admins || []).forEach(function (a) { row(tb, [txt(a.name), day(a.since || a.joined), pill(d.one_admin ? 'The only administrator' : 'Administrator', 'm')]); });
      ac.textContent = '';
    }
    (d.activity || []).forEach(function (a) {
      var what = (ACTIONS[a.action] || txt(a.action)) + (a.detail && a.detail.tab ? ' · ' + txt(a.detail.tab) : '') + (a.detail && a.detail.status ? ' (' + txt(a.detail.status) + ')' : '');
      row(ac, [ago(a.at), txt(a.by) || '–', what]);
    });
    var si = $('signin'); si.textContent = '';
    (d.signin || []).forEach(function (e) { row(si, [ago(e.at), txt(e.member) || '–', txt(e.what)]); });
    $('signin-empty').hidden = si.children.length > 0;
    if (!more) locks(d.locks || []);
  }
  // 053: the locks in force, each released with a reason (POST /api/work/unlock; the database records it).
  function locks(list) {
    var lt = $('locks'); lt.textContent = '';
    list.forEach(function (l) {
      if (!isId(l.member)) return;
      var box = document.createElement('span');
      var why = document.createElement('input');
      why.type = 'text'; why.maxLength = 200; why.placeholder = 'Reason'; why.setAttribute('aria-label', 'Reason to release ' + txt(l.name));
      var go = document.createElement('button');
      go.type = 'button'; go.textContent = 'Release'; go.setAttribute('aria-label', 'Release ' + (txt(l.name) || 'this member'));
      go.addEventListener('click', function () {
        var r = why.value.trim();
        if (r.length < 3) { $('locks-status').textContent = 'Give a reason of at least 3 characters.'; why.focus(); return; }
        go.disabled = true;
        fetch('/api/work/unlock', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ member: l.member, reason: r }) })
          .then(function (x) { return x.json().then(function (d) { return { ok: x.ok, d: d }; }, function () { return { ok: false, d: {} }; }); })
          .then(function (x) {
            go.disabled = false;
            if (!x.ok) { $('locks-status').textContent = typeof x.d.error === 'string' ? x.d.error : 'The lock couldn’t be released.'; return; }
            $('locks-status').textContent = x.d.result === 'released' ? 'Released: ' + txt(l.name) + ' can sign in again.' : 'That lock had already ended.';
            // The list redraws without this button: keep keyboard focus on the result.
            $('locks-status').focus();
            open('admins');
          }, function () { go.disabled = false; $('locks-status').textContent = 'The console couldn’t be reached. Please try again.'; });
      });
      box.appendChild(why); box.appendChild(document.createTextNode(' ')); box.appendChild(go);
      row(lt, [txt(l.name) || '–', ago(l.locked_at), clock(l.until) + ' UTC', box]);
    });
    $('locks-empty').hidden = lt.children.length > 0;
  }

  var DRAW = { summary: summary, agents: agents, projects: tasks, submissions: subs, ledger: ledger, admins: admins };
  var status = '';
  // "Show older": each list's button, and the cursor its last page gave (the last row's time and id).
  var MORE = { agents: 'agents-more', projects: 'tasks-more', submissions: 'subs-more', ledger: 'entries-more', admins: 'activity-more' };
  var next = {};
  function paged(tab, d) {
    next[tab] = d && typeof d.next === 'string' ? d.next : null;
    if (MORE[tab]) $(MORE[tab]).hidden = !next[tab];
  }
  function more(tab) {
    if (!next[tab]) return;
    var b = $(MORE[tab]); b.disabled = true;
    load(tab, (tab === 'projects' && status ? '&status=' + status : '') + '&cursor=' + encodeURIComponent(next[tab])).then(function (d) {
      b.disabled = false;
      if (d && DRAW[tab]) { DRAW[tab](d, true); paged(tab, d); }
    });
  }
  function open(tab) {
    Array.prototype.forEach.call(document.querySelectorAll('[role="tab"][data-tab]'), function (b) {
      var on = b.getAttribute('data-tab') === tab;
      b.className = on ? 'on' : ''; b.setAttribute('aria-selected', on ? 'true' : 'false'); b.tabIndex = on ? 0 : -1;
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-panel]'), function (p) { p.hidden = p.getAttribute('data-panel') !== tab; });
    if (MORE[tab]) $(MORE[tab]).hidden = true;
    load(tab, tab === 'projects' && status ? '&status=' + status : '').then(function (d) { if (d && DRAW[tab]) { DRAW[tab](d, false); paged(tab, d); } });
  }
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"][data-tab]'));
  tabs.forEach(function (b, i) {
    b.addEventListener('click', function () { open(b.getAttribute('data-tab')); });
    b.addEventListener('keydown', function (e) {
      var k = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!k) return;
      e.preventDefault();
      var next = tabs[(i + k + tabs.length) % tabs.length];
      next.focus(); open(next.getAttribute('data-tab'));
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('#chips button'), function (b) {
    b.addEventListener('click', function () {
      status = b.getAttribute('data-status') || '';
      Array.prototype.forEach.call(document.querySelectorAll('#chips button'), function (c) { var on = c === b; c.className = on ? 'on' : ''; c.setAttribute('aria-pressed', on ? 'true' : 'false'); });
      open('projects');
    });
  });
  $('agents-q').addEventListener('input', drawAgents);
  $('subs-q').addEventListener('input', drawSubs);
  $('recheck').addEventListener('click', function () { open('ledger'); });
  Object.keys(MORE).forEach(function (tab) { $(MORE[tab]).addEventListener('click', function () { more(tab); }); });
  open('summary');
})();
